.class public abstract Ltj/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;

.field public static final c:Lt2/b;

.field public static final d:Lt2/b;

.field public static final e:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltf0/a;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lt2/b;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const v3, -0x1044200d

    .line 11
    .line 12
    .line 13
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 14
    .line 15
    .line 16
    sput-object v1, Ltj/a;->a:Lt2/b;

    .line 17
    .line 18
    new-instance v0, Ltf0/a;

    .line 19
    .line 20
    const/4 v1, 0x4

    .line 21
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lt2/b;

    .line 25
    .line 26
    const v3, -0x549c2580

    .line 27
    .line 28
    .line 29
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Ltj/a;->b:Lt2/b;

    .line 33
    .line 34
    new-instance v0, Ltf0/a;

    .line 35
    .line 36
    const/4 v1, 0x5

    .line 37
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 38
    .line 39
    .line 40
    new-instance v1, Lt2/b;

    .line 41
    .line 42
    const v3, 0x56c1a99b

    .line 43
    .line 44
    .line 45
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 46
    .line 47
    .line 48
    sput-object v1, Ltj/a;->c:Lt2/b;

    .line 49
    .line 50
    new-instance v0, Ltf0/a;

    .line 51
    .line 52
    const/4 v1, 0x6

    .line 53
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 54
    .line 55
    .line 56
    new-instance v1, Lt2/b;

    .line 57
    .line 58
    const v3, 0x78d48b2a

    .line 59
    .line 60
    .line 61
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 62
    .line 63
    .line 64
    sput-object v1, Ltj/a;->d:Lt2/b;

    .line 65
    .line 66
    new-instance v0, Ltf0/a;

    .line 67
    .line 68
    const/4 v1, 0x7

    .line 69
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 70
    .line 71
    .line 72
    new-instance v1, Lt2/b;

    .line 73
    .line 74
    const v3, 0xf4a4f08

    .line 75
    .line 76
    .line 77
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 78
    .line 79
    .line 80
    sput-object v1, Ltj/a;->e:Lt2/b;

    .line 81
    .line 82
    return-void
.end method

.method public static final a(Lki/k;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, La8/r0;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    const-string p0, "http://10.0.2.2:8080/mock/"

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_1
    const-string p0, "http://10.0.2.2:8080/"

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_2
    const-string p0, "https://dev.emea.mobile.charging.cariad.digital/mock/"

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_3
    const-string p0, "https://prod.emea.mobile.charging.cariad.digital/"

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_4
    const-string p0, "https://stage.emea.mobile.charging.cariad.digital/"

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_5
    const-string p0, "https://test.emea.mobile.charging.cariad.digital/"

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_6
    const-string p0, "https://dev.emea.mobile.charging.cariad.digital/"

    .line 33
    .line 34
    return-object p0

    .line 35
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
