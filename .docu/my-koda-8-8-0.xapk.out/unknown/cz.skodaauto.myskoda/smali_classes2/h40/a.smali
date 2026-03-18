.class public final enum Lh40/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum f:Lh40/a;

.field public static final enum g:Lh40/a;

.field public static final enum h:Lh40/a;

.field public static final synthetic i:[Lh40/a;


# instance fields
.field public final d:Li91/k1;

.field public final e:I


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lh40/a;

    .line 2
    .line 3
    sget-object v1, Li91/k1;->d:Li91/k1;

    .line 4
    .line 5
    const v2, 0x7f120cd9

    .line 6
    .line 7
    .line 8
    const-string v3, "WaitingForPickup"

    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    invoke-direct {v0, v3, v4, v1, v2}, Lh40/a;-><init>(Ljava/lang/String;ILi91/k1;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lh40/a;->f:Lh40/a;

    .line 15
    .line 16
    new-instance v1, Lh40/a;

    .line 17
    .line 18
    sget-object v2, Li91/k1;->f:Li91/k1;

    .line 19
    .line 20
    const v3, 0x7f120cd8

    .line 21
    .line 22
    .line 23
    const-string v4, "AwaitingConfirmation"

    .line 24
    .line 25
    const/4 v5, 0x1

    .line 26
    invoke-direct {v1, v4, v5, v2, v3}, Lh40/a;-><init>(Ljava/lang/String;ILi91/k1;I)V

    .line 27
    .line 28
    .line 29
    sput-object v1, Lh40/a;->g:Lh40/a;

    .line 30
    .line 31
    new-instance v2, Lh40/a;

    .line 32
    .line 33
    sget-object v3, Li91/k1;->g:Li91/k1;

    .line 34
    .line 35
    const v4, 0x7f120cd7

    .line 36
    .line 37
    .line 38
    const-string v5, "Cancelled"

    .line 39
    .line 40
    const/4 v6, 0x2

    .line 41
    invoke-direct {v2, v5, v6, v3, v4}, Lh40/a;-><init>(Ljava/lang/String;ILi91/k1;I)V

    .line 42
    .line 43
    .line 44
    sput-object v2, Lh40/a;->h:Lh40/a;

    .line 45
    .line 46
    filled-new-array {v0, v1, v2}, [Lh40/a;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    sput-object v0, Lh40/a;->i:[Lh40/a;

    .line 51
    .line 52
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILi91/k1;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lh40/a;->d:Li91/k1;

    .line 5
    .line 6
    iput p4, p0, Lh40/a;->e:I

    .line 7
    .line 8
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lh40/a;
    .locals 1

    .line 1
    const-class v0, Lh40/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lh40/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lh40/a;
    .locals 1

    .line 1
    sget-object v0, Lh40/a;->i:[Lh40/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lh40/a;

    .line 8
    .line 9
    return-object v0
.end method
