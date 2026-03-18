.class public final enum Lq60/c;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic e:[Lq60/c;

.field public static final synthetic f:Lsx0/b;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lq60/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "myskoda://redirect/parkfuel/registration-success"

    .line 5
    .line 6
    const-string v3, "SuccessLink"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lq60/c;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lq60/c;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    const-string v3, "myskoda://redirect/parkfuel/registration-cancel"

    .line 15
    .line 16
    const-string v4, "CancelLink"

    .line 17
    .line 18
    invoke-direct {v1, v4, v2, v3}, Lq60/c;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    filled-new-array {v0, v1}, [Lq60/c;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lq60/c;->e:[Lq60/c;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lq60/c;->f:Lsx0/b;

    .line 32
    .line 33
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lq60/c;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lq60/c;
    .locals 1

    .line 1
    const-class v0, Lq60/c;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lq60/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lq60/c;
    .locals 1

    .line 1
    sget-object v0, Lq60/c;->e:[Lq60/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lq60/c;

    .line 8
    .line 9
    return-object v0
.end method
