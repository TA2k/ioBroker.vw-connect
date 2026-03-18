.class public final Lc7/g;
.super Landroidx/glance/appwidget/protobuf/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_INSTANCE:Lc7/g;

.field public static final LAYOUT_FIELD_NUMBER:I = 0x1

.field public static final LAYOUT_INDEX_FIELD_NUMBER:I = 0x2

.field private static volatile PARSER:Landroidx/glance/appwidget/protobuf/r0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/glance/appwidget/protobuf/r0;"
        }
    .end annotation
.end field


# instance fields
.field private bitField0_:I

.field private layoutIndex_:I

.field private layout_:Lc7/i;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lc7/g;

    .line 2
    .line 3
    invoke-direct {v0}, Landroidx/glance/appwidget/protobuf/u;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc7/g;->DEFAULT_INSTANCE:Lc7/g;

    .line 7
    .line 8
    const-class v1, Lc7/g;

    .line 9
    .line 10
    invoke-static {v1, v0}, Landroidx/glance/appwidget/protobuf/u;->i(Ljava/lang/Class;Landroidx/glance/appwidget/protobuf/u;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static k(Lc7/g;Lc7/i;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lc7/g;->layout_:Lc7/i;

    .line 8
    .line 9
    iget p1, p0, Lc7/g;->bitField0_:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    iput p1, p0, Lc7/g;->bitField0_:I

    .line 14
    .line 15
    return-void
.end method

.method public static l(Lc7/g;I)V
    .locals 0

    .line 1
    iput p1, p0, Lc7/g;->layoutIndex_:I

    .line 2
    .line 3
    return-void
.end method

.method public static o()Lc7/f;
    .locals 2

    .line 1
    sget-object v0, Lc7/g;->DEFAULT_INSTANCE:Lc7/g;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-virtual {v0, v1}, Lc7/g;->b(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Landroidx/glance/appwidget/protobuf/s;

    .line 9
    .line 10
    check-cast v0, Lc7/f;

    .line 11
    .line 12
    return-object v0
.end method


# virtual methods
.method public final b(I)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-static {p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    sget-object p0, Lc7/g;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lc7/g;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lc7/g;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    new-instance p0, Landroidx/glance/appwidget/protobuf/t;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object p0, Lc7/g;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    :goto_0
    monitor-exit p1

    .line 36
    return-object p0

    .line 37
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0

    .line 39
    :cond_1
    return-object p0

    .line 40
    :pswitch_1
    sget-object p0, Lc7/g;->DEFAULT_INSTANCE:Lc7/g;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    new-instance p0, Lc7/f;

    .line 44
    .line 45
    sget-object p1, Lc7/g;->DEFAULT_INSTANCE:Lc7/g;

    .line 46
    .line 47
    invoke-direct {p0, p1}, Landroidx/glance/appwidget/protobuf/s;-><init>(Landroidx/glance/appwidget/protobuf/u;)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_3
    new-instance p0, Lc7/g;

    .line 52
    .line 53
    invoke-direct {p0}, Landroidx/glance/appwidget/protobuf/u;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    const-string p0, "bitField0_"

    .line 58
    .line 59
    const-string p1, "layout_"

    .line 60
    .line 61
    const-string v0, "layoutIndex_"

    .line 62
    .line 63
    filled-new-array {p0, p1, v0}, [Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const-string p1, "\u0000\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001\u1009\u0000\u0002\u0004"

    .line 68
    .line 69
    sget-object v0, Lc7/g;->DEFAULT_INSTANCE:Lc7/g;

    .line 70
    .line 71
    new-instance v1, Landroidx/glance/appwidget/protobuf/u0;

    .line 72
    .line 73
    invoke-direct {v1, v0, p1, p0}, Landroidx/glance/appwidget/protobuf/u0;-><init>(Landroidx/glance/appwidget/protobuf/u;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    return-object v1

    .line 77
    :pswitch_5
    const/4 p0, 0x0

    .line 78
    return-object p0

    .line 79
    :pswitch_6
    const/4 p0, 0x1

    .line 80
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final m()Lc7/i;
    .locals 0

    .line 1
    iget-object p0, p0, Lc7/g;->layout_:Lc7/i;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lc7/i;->v()Lc7/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final n()I
    .locals 0

    .line 1
    iget p0, p0, Lc7/g;->layoutIndex_:I

    .line 2
    .line 3
    return p0
.end method
