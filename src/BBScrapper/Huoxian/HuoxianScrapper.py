import logging
import time
import traceback
from datetime import datetime, date
from sqlalchemy import select
import requests
import json

from BBScrapper.model import DBSession, Program, Report, User, Backup

SOURCE = "Huoxian"
PROXIES = {"http": "http://localhost:8080", "https": "http://localhost:8080"}

"""
    Translations:
"""

SHOW_TYPES_TO_ACTION = {
    3: "accepted",
    5: "won",
    # idk -> TuTuTu 在 火线安全应急响应中心 获得了 火线2020年度查克拉分红 / TuTuTu received the 2020 Chakra dividend at the Fire Line Safety Emergency Response Center
    6: "chakra added",
    9: "new",
    16: "bounty paid"
}

REP_LEAK_LEVEL = {
    # for program trends:
    "未知报告": "Unknown",
    "低危报告": "Low",
    "中危报告": "Medium",
    "高危报告": "High",
    # todo: Severe Report == Critical??
    "严重报告": "Critical",
    # for user trends:
    "未知": "Unknown",
    "低危": "Low",
    "中危": "Medium",
    "高危": "High",
    "严重": "Critical"
}

TRANSLATIONS = {
    # Time
    "天": " day ",
    "年": " year ",
    "月": " month ",
    "前": "ago",
}

ID2STATE = {
    1: "In progress",
    3: "Closed"
}


def translate(string):
    for key, value in TRANSLATIONS.items():
        string = string.replace(key, value)
    return string


class HuoxianScrapper:

    def __init__(self, logger, teleBot) -> None:
        self.db_session = DBSession()
        self.log = logger
        self.headers = {}
        self.scraped_users = []
        self.proxies = PROXIES
        self.session = requests.session()
        self.teleBot = teleBot

    def scrape_programs(self):
        self.log.info("Currently scraping all programs...")
        url = "https://www.huoxian.cn/fireapi/fireapp/projectList/"
        data = {"page": 1, "page_size": 1000}
        res = self.session.post(url, json=data)
        programs = res.json()

        known_programs = []
        for program in programs["data"]["results"]:
            known_programs.append(program['id'])
            self.parse_program(program)
            time.sleep(0.1)

        # try to get information about other programs by enumerating them
        for enum_id in range(1, 1000):
            if str(enum_id) not in known_programs:
                program = {
                    "name": f"Enum Program {enum_id}",
                    "id": f"{enum_id}"
                }
                self.parse_program(program)
                enum_id += 1

    def parse_program(self, program):
        projectDetails = True
        projectAssetsNum = True
        states = {
            "该项目不存在，如有疑问请联系火线小助手": "NotExisting",
            "该项目不允许匿名查看，请登录后查看": "DoesNotAllowAnonymousWatching",
            "项目已结束": "ProjectEnded",
            "项目已结束，如有疑问请联系火线小助手": "ProjectEnded",
            "该项目为私密项目，请联系火线小助手申请加入": "PrivateProgram"
        }

        pid = program["id"]
        name = program['name']
        try:
            self.log.info("Currently parsing program: " + name)

            url = "https://www.huoxian.cn/fireapi/fireapp/projectDetail/"
            data = {"pid": pid}
            res_details = self.session.post(url, json=data)
            if res_details.status_code != 200 or ('data' not in res_details.json()) \
                    or (len(res_details.json()['data']) == 0):
                # check for program enumeration if we can infer data of the message/response
                if 'msg' in res_details.json():
                    msg = "No message found"
                    if 'msg' not in res_details.json() or res_details.json()['msg'] not in states.keys():
                        if 'msg' in res_details.json() and res_details.json()['msg'] not in states.keys():
                            msg = res_details.json()['msg']
                        self.log.warning(f"Can't be scraped because: Message = {msg}")
                        return
                    else:
                        # only store if not "not existing"
                        msg = res_details.json()['msg']
                        if states[msg] == "NotExisting":
                            return

                        # store the enumerated programs as well
                        db_program = self.db_session.query(Program).filter_by(
                            programId=pid,
                            source=SOURCE
                        ).first()

                        if not db_program:
                            db_program = Program(
                                programId=pid,
                                handle=program['name'],
                                state=states[msg],
                                source=SOURCE,
                            )
                            self.db_session.add(db_program)
                            self.db_session.commit()
                        return
                # case if no enum program
                else:
                    self.log.warning(f"Warning fetching more data (projectDetail) of program: {name} failed!")
                    projectDetails = False

            res_assetNum = self.session.post(
                'https://www.huoxian.cn/fireapi/fireapp/projectAssetsNum/',
                json=data,
            )
            if res_assetNum.status_code != 200 or ('data' not in res_assetNum.json()):
                self.log.warning(f"Warning fetching more data (projectAssetsNum) of program: {name} failed!")
                projectAssetsNum = False

            # store to DB
            # check if already contained:
            db_program = self.db_session.query(Program).filter_by(
                programId=pid,
                source=SOURCE
            ).first()

            currency = "Unknown"
            if projectDetails and len(res_details.json()['data']) > 0:
                program["projectDetail"] = res_details.json()['data']
                # Chinese Yuan Renminbi/ RMB to Dollar avg in last year = 0.15 / 1
                min_reward = program['projectDetail'][0]['reward'][0]['lowLow']
                # Removed calculation -> done in analysis
                if "元" in min_reward:
                    min_reward = float(min_reward.replace("元", ""))
                    currency = "RMB"
                if min_reward == '':
                    min_reward = None
                max_reward = program['projectDetail'][0]['reward'][0]['seriousMax']
                if "元" in max_reward:
                    max_reward = float(max_reward.replace("元", ""))
                    currency = "RMB"
                if max_reward == '':
                    max_reward = None
            else:
                min_reward = None
                max_reward = None

            if projectAssetsNum and len(res_assetNum.json()['data']) > 0:
                program["projectAssetsNum"] = res_assetNum.json()['data']
                user_count = program['projectAssetsNum']['usercount']
                bug_count = program['projectAssetsNum']['effectiveReport']
            else:
                user_count = None
                bug_count = None

            if program['status']['id'] not in ID2STATE.keys():
                self.log.error("Status is not known yet! ID:" + str(program['status']['id']) +
                               " Value: " + str(program['status']['value']))
                ID2STATE[program['status']['id']] = program['status']['value']

            if not db_program:
                db_program = Program(
                    programId=pid,
                    handle=program['name'],
                    state=ID2STATE[program['status']['id']],  # todo map this to a real state
                    numberJoined=user_count,
                    bugCountValid=bug_count,
                    maxReward=max_reward,
                    minReward=min_reward,
                    currency=currency,
                    launchedAt=program['begintime'],
                    stoppedAt=program['endtime'],
                    source=SOURCE,
                )
                self.db_session.add(db_program)
            else:
                db_program.state = ID2STATE[program['status']['id']]  # todo map this to a real state
                db_program.numberJoined = user_count
                db_program.bugCountValid = bug_count
                db_program.maxReward = max_reward
                db_program.minReward = min_reward
                db_program.currency = currency
                db_program.launchedAt = program['begintime']
                db_program.stoppedAt = program['endtime']

            self.db_session.commit()

            # backup program data
            db_backup = Backup(
                source=SOURCE,
                type="program",
                identifier=f"{program['name']}-{program['projectCode']}",
                date=str(date.today()),
                data=json.dumps(program)
            )
            self.db_session.add(db_backup)
            self.db_session.commit()

        except Exception:
            self.log.error(f'Exception caught! \n {traceback.format_exc()}')
            return

    def run(self):
        self.log.info("---- HuoxianScrapper started ----")
        self.teleBot.info("HuoxianScrapper started")

        # GET PROGRAMS
        self.teleBot.info("Scraping all programs...")
        self.scrape_programs()

        self.log.info("---- HuoxianScrapper finished ----")
        self.teleBot.info("Huoxian finished")
