.class public final enum Lqb/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lqb/a;

.field public static final synthetic f:[Lqb/a;


# instance fields
.field public final d:[I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lqb/a;

    .line 2
    .line 3
    const/16 v1, 0x100

    .line 4
    .line 5
    filled-new-array {v1}, [I

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-direct {v0, v1}, Lqb/a;-><init>([I)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lqb/a;->e:Lqb/a;

    .line 13
    .line 14
    filled-new-array {v0}, [Lqb/a;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lqb/a;->f:[Lqb/a;

    .line 19
    .line 20
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public varargs constructor <init>([I)V
    .locals 2

    .line 1
    const-string v0, "QR_CODE"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lqb/a;->d:[I

    .line 8
    .line 9
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lqb/a;
    .locals 1

    .line 1
    const-class v0, Lqb/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqb/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lqb/a;
    .locals 1

    .line 1
    sget-object v0, Lqb/a;->f:[Lqb/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lqb/a;

    .line 8
    .line 9
    return-object v0
.end method
