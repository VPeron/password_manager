from prettytable import PrettyTable


def frame(columns: list, rows):
    display_frame = PrettyTable(columns)
    if type(rows[0]) == list:
        display_frame.add_rows(rows)
    elif type(rows[0]) == str:
        display_frame.add_row(rows)
    print(display_frame)
