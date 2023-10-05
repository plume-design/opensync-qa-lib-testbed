from matplotlib import pyplot


class PlotterSerie:
    def __init__(self, x_values, y_values):
        self.x_values = x_values
        self.y_values = y_values


class Plotter:
    def __init__(self, x_axis_title, y_axis_title):
        self.x_axis_title = x_axis_title
        self.y_axis_title = y_axis_title

    def add_series(self, series):
        if not isinstance(series, list):
            series = [series]

        for serie in series:
            pyplot.plot(serie.x_values, serie.y_values)

    def show(self):
        pyplot.xlabel(self.x_axis_title)
        pyplot.ylabel(self.y_axis_title)
        pyplot.show()

    def save_to_file(self, filename):
        pyplot.xlabel(self.x_axis_title)
        pyplot.ylabel(self.y_axis_title)
        pyplot.savefig(filename, format="png", dpi=300)
        pyplot.clf()
        return filename
