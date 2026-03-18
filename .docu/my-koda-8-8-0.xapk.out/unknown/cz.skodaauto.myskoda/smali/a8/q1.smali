.class public final La8/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:La8/q1;


# instance fields
.field public final a:Lhr/k0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, La0/j;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, La0/j;-><init>(IZ)V

    .line 6
    .line 7
    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x5

    .line 13
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    const/4 v3, 0x2

    .line 18
    filled-new-array {v1, v2}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-static {v3, v1}, Lhr/k0;->o(I[Ljava/lang/Object;)Lhr/k0;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    iput-object v1, v0, La0/j;->e:Ljava/lang/Object;

    .line 27
    .line 28
    new-instance v1, La8/q1;

    .line 29
    .line 30
    invoke-direct {v1, v0}, La8/q1;-><init>(La0/j;)V

    .line 31
    .line 32
    .line 33
    sput-object v1, La8/q1;->b:La8/q1;

    .line 34
    .line 35
    return-void
.end method

.method public constructor <init>(La0/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object p1, p1, La0/j;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p1, Lhr/k0;

    .line 7
    .line 8
    iput-object p1, p0, La8/q1;->a:Lhr/k0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, La8/q1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    check-cast p1, La8/q1;

    .line 7
    .line 8
    iget-object p0, p0, La8/q1;->a:Lhr/k0;

    .line 9
    .line 10
    iget-object p1, p1, La8/q1;->a:Lhr/k0;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lhr/k0;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final hashCode()I
    .locals 7

    .line 1
    const/4 v2, 0x0

    .line 2
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 3
    .line 4
    iget-object v0, p0, La8/q1;->a:Lhr/k0;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    move-object v4, v3

    .line 8
    move-object v5, v3

    .line 9
    move-object v6, v3

    .line 10
    filled-new-array/range {v0 .. v6}, [Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-static {p0}, Ljava/util/Objects;->hash([Ljava/lang/Object;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method
