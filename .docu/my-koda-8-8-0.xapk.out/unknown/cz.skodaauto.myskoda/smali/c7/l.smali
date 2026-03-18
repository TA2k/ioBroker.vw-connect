.class public final Lc7/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/u0;


# static fields
.field public static final a:Lc7/l;

.field public static final b:Lc7/e;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lc7/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc7/l;->a:Lc7/l;

    .line 7
    .line 8
    invoke-static {}, Lc7/e;->n()Lc7/e;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "getDefaultInstance()"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lc7/l;->b:Lc7/e;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Lc7/l;->b:Lc7/e;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b(Ljava/io/FileInputStream;)Ljava/lang/Object;
    .locals 1

    .line 1
    :try_start_0
    invoke-static {p1}, Lc7/e;->q(Ljava/io/FileInputStream;)Lc7/e;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Landroidx/glance/appwidget/protobuf/a0; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    move-exception p0

    .line 7
    new-instance p1, Lm6/b;

    .line 8
    .line 9
    const-string v0, "Cannot read proto."

    .line 10
    .line 11
    invoke-direct {p1, v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 12
    .line 13
    .line 14
    throw p1
.end method

.method public final c(Ljava/lang/Object;Lm6/b1;)V
    .locals 1

    .line 1
    check-cast p1, Lc7/e;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    invoke-virtual {p1, p0}, Landroidx/glance/appwidget/protobuf/u;->a(Landroidx/glance/appwidget/protobuf/v0;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    sget-object v0, Landroidx/glance/appwidget/protobuf/j;->f:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const/16 v0, 0x1000

    .line 14
    .line 15
    if-le p0, v0, :cond_0

    .line 16
    .line 17
    move p0, v0

    .line 18
    :cond_0
    new-instance v0, Landroidx/glance/appwidget/protobuf/j;

    .line 19
    .line 20
    invoke-direct {v0, p2, p0}, Landroidx/glance/appwidget/protobuf/j;-><init>(Lm6/b1;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    sget-object p0, Landroidx/glance/appwidget/protobuf/s0;->c:Landroidx/glance/appwidget/protobuf/s0;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    invoke-virtual {p0, p2}, Landroidx/glance/appwidget/protobuf/s0;->a(Ljava/lang/Class;)Landroidx/glance/appwidget/protobuf/v0;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    iget-object p2, v0, Landroidx/glance/appwidget/protobuf/j;->a:Landroidx/glance/appwidget/protobuf/h0;

    .line 40
    .line 41
    if-eqz p2, :cond_1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    new-instance p2, Landroidx/glance/appwidget/protobuf/h0;

    .line 45
    .line 46
    invoke-direct {p2, v0}, Landroidx/glance/appwidget/protobuf/h0;-><init>(Landroidx/glance/appwidget/protobuf/j;)V

    .line 47
    .line 48
    .line 49
    :goto_0
    invoke-interface {p0, p1, p2}, Landroidx/glance/appwidget/protobuf/v0;->g(Ljava/lang/Object;Landroidx/glance/appwidget/protobuf/h0;)V

    .line 50
    .line 51
    .line 52
    iget p0, v0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 53
    .line 54
    if-lez p0, :cond_2

    .line 55
    .line 56
    invoke-virtual {v0}, Landroidx/glance/appwidget/protobuf/j;->m()V

    .line 57
    .line 58
    .line 59
    :cond_2
    return-void
.end method
