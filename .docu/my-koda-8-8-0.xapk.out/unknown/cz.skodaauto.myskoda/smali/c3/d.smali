.class public final Lc3/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lc3/d;->a:I

    .line 5
    .line 6
    return-void
.end method

.method public static a(I)Ljava/lang/String;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, v0, :cond_0

    .line 3
    .line 4
    const-string p0, "Next"

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    const/4 v0, 0x2

    .line 8
    if-ne p0, v0, :cond_1

    .line 9
    .line 10
    const-string p0, "Previous"

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_1
    const/4 v0, 0x3

    .line 14
    if-ne p0, v0, :cond_2

    .line 15
    .line 16
    const-string p0, "Left"

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_2
    const/4 v0, 0x4

    .line 20
    if-ne p0, v0, :cond_3

    .line 21
    .line 22
    const-string p0, "Right"

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_3
    const/4 v0, 0x5

    .line 26
    if-ne p0, v0, :cond_4

    .line 27
    .line 28
    const-string p0, "Up"

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_4
    const/4 v0, 0x6

    .line 32
    if-ne p0, v0, :cond_5

    .line 33
    .line 34
    const-string p0, "Down"

    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_5
    const/4 v0, 0x7

    .line 38
    if-ne p0, v0, :cond_6

    .line 39
    .line 40
    const-string p0, "Enter"

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_6
    const/16 v0, 0x8

    .line 44
    .line 45
    if-ne p0, v0, :cond_7

    .line 46
    .line 47
    const-string p0, "Exit"

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_7
    const-string p0, "Invalid FocusDirection"

    .line 51
    .line 52
    return-object p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lc3/d;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    check-cast p1, Lc3/d;

    .line 7
    .line 8
    iget p1, p1, Lc3/d;->a:I

    .line 9
    .line 10
    iget p0, p0, Lc3/d;->a:I

    .line 11
    .line 12
    if-eq p0, p1, :cond_1

    .line 13
    .line 14
    :goto_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lc3/d;->a:I

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lc3/d;->a:I

    .line 2
    .line 3
    invoke-static {p0}, Lc3/d;->a(I)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
