.class public final enum Lmq0/b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lmq0/b;

.field public static final enum f:Lmq0/b;

.field public static final enum g:Lmq0/b;

.field public static final synthetic h:[Lmq0/b;

.field public static final synthetic i:Lsx0/b;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lmq0/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "start_climate_control"

    .line 5
    .line 6
    const-string v3, "StartAirCondition"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lmq0/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lmq0/b;->e:Lmq0/b;

    .line 12
    .line 13
    new-instance v1, Lmq0/b;

    .line 14
    .line 15
    const-string v2, "HonkFlash"

    .line 16
    .line 17
    const/4 v3, 0x1

    .line 18
    invoke-direct {v1, v2, v3, v2}, Lmq0/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    sput-object v1, Lmq0/b;->f:Lmq0/b;

    .line 22
    .line 23
    new-instance v2, Lmq0/b;

    .line 24
    .line 25
    const-string v3, "Flash"

    .line 26
    .line 27
    const/4 v4, 0x2

    .line 28
    invoke-direct {v2, v3, v4, v3}, Lmq0/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    sput-object v2, Lmq0/b;->g:Lmq0/b;

    .line 32
    .line 33
    filled-new-array {v0, v1, v2}, [Lmq0/b;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sput-object v0, Lmq0/b;->h:[Lmq0/b;

    .line 38
    .line 39
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lmq0/b;->i:Lsx0/b;

    .line 44
    .line 45
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lmq0/b;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lmq0/b;
    .locals 1

    .line 1
    const-class v0, Lmq0/b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lmq0/b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lmq0/b;
    .locals 1

    .line 1
    sget-object v0, Lmq0/b;->h:[Lmq0/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lmq0/b;

    .line 8
    .line 9
    return-object v0
.end method
