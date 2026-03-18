.class public final Landroidx/glance/appwidget/protobuf/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(JLjava/lang/Object;)Landroidx/glance/appwidget/protobuf/x;
    .locals 2

    .line 1
    sget-object v0, Landroidx/glance/appwidget/protobuf/e1;->c:Landroidx/glance/appwidget/protobuf/d1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Landroidx/glance/appwidget/protobuf/d1;->h(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroidx/glance/appwidget/protobuf/x;

    .line 8
    .line 9
    move-object v1, v0

    .line 10
    check-cast v1, Landroidx/glance/appwidget/protobuf/b;

    .line 11
    .line 12
    iget-boolean v1, v1, Landroidx/glance/appwidget/protobuf/b;->d:Z

    .line 13
    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-nez v1, :cond_0

    .line 21
    .line 22
    const/16 v1, 0xa

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    mul-int/lit8 v1, v1, 0x2

    .line 26
    .line 27
    :goto_0
    check-cast v0, Landroidx/glance/appwidget/protobuf/t0;

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Landroidx/glance/appwidget/protobuf/t0;->g(I)Landroidx/glance/appwidget/protobuf/t0;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-static {p2, p0, p1, v0}, Landroidx/glance/appwidget/protobuf/e1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    return-object v0
.end method
