.class public final enum Landroidx/lifecycle/p;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Landroidx/lifecycle/p;

.field public static final Companion:Landroidx/lifecycle/n;

.field public static final enum ON_ANY:Landroidx/lifecycle/p;

.field public static final enum ON_CREATE:Landroidx/lifecycle/p;

.field public static final enum ON_DESTROY:Landroidx/lifecycle/p;

.field public static final enum ON_PAUSE:Landroidx/lifecycle/p;

.field public static final enum ON_RESUME:Landroidx/lifecycle/p;

.field public static final enum ON_START:Landroidx/lifecycle/p;

.field public static final enum ON_STOP:Landroidx/lifecycle/p;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Landroidx/lifecycle/p;

    .line 2
    .line 3
    const-string v1, "ON_CREATE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Landroidx/lifecycle/p;->ON_CREATE:Landroidx/lifecycle/p;

    .line 10
    .line 11
    new-instance v1, Landroidx/lifecycle/p;

    .line 12
    .line 13
    const-string v2, "ON_START"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;

    .line 20
    .line 21
    new-instance v2, Landroidx/lifecycle/p;

    .line 22
    .line 23
    const-string v3, "ON_RESUME"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Landroidx/lifecycle/p;->ON_RESUME:Landroidx/lifecycle/p;

    .line 30
    .line 31
    new-instance v3, Landroidx/lifecycle/p;

    .line 32
    .line 33
    const-string v4, "ON_PAUSE"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Landroidx/lifecycle/p;->ON_PAUSE:Landroidx/lifecycle/p;

    .line 40
    .line 41
    new-instance v4, Landroidx/lifecycle/p;

    .line 42
    .line 43
    const-string v5, "ON_STOP"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;

    .line 50
    .line 51
    new-instance v5, Landroidx/lifecycle/p;

    .line 52
    .line 53
    const-string v6, "ON_DESTROY"

    .line 54
    .line 55
    const/4 v7, 0x5

    .line 56
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v5, Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;

    .line 60
    .line 61
    new-instance v6, Landroidx/lifecycle/p;

    .line 62
    .line 63
    const-string v7, "ON_ANY"

    .line 64
    .line 65
    const/4 v8, 0x6

    .line 66
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v6, Landroidx/lifecycle/p;->ON_ANY:Landroidx/lifecycle/p;

    .line 70
    .line 71
    filled-new-array/range {v0 .. v6}, [Landroidx/lifecycle/p;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    sput-object v0, Landroidx/lifecycle/p;->$VALUES:[Landroidx/lifecycle/p;

    .line 76
    .line 77
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    sput-object v0, Landroidx/lifecycle/p;->$ENTRIES:Lsx0/a;

    .line 82
    .line 83
    new-instance v0, Landroidx/lifecycle/n;

    .line 84
    .line 85
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 86
    .line 87
    .line 88
    sput-object v0, Landroidx/lifecycle/p;->Companion:Landroidx/lifecycle/n;

    .line 89
    .line 90
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Landroidx/lifecycle/p;
    .locals 1

    .line 1
    const-class v0, Landroidx/lifecycle/p;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroidx/lifecycle/p;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Landroidx/lifecycle/p;
    .locals 1

    .line 1
    sget-object v0, Landroidx/lifecycle/p;->$VALUES:[Landroidx/lifecycle/p;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Landroidx/lifecycle/p;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final a()Landroidx/lifecycle/q;
    .locals 2

    .line 1
    sget-object v0, Landroidx/lifecycle/o;->a:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    aget v0, v0, v1

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance p0, La8/r0;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 15
    .line 16
    .line 17
    throw p0

    .line 18
    :pswitch_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    new-instance v1, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string p0, " has no target state"

    .line 29
    .line 30
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw v0

    .line 41
    :pswitch_1
    sget-object p0, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_2
    sget-object p0, Landroidx/lifecycle/q;->h:Landroidx/lifecycle/q;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_3
    sget-object p0, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_4
    sget-object p0, Landroidx/lifecycle/q;->f:Landroidx/lifecycle/q;

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_4
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
