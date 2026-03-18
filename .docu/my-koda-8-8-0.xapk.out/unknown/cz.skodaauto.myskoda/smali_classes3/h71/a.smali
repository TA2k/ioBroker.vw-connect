.class public final enum Lh71/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lh71/a;

.field public static final enum e:Lh71/a;

.field public static final synthetic f:[Lh71/a;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh71/a;

    .line 2
    .line 3
    const-string v1, "Primary"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lh71/a;->d:Lh71/a;

    .line 10
    .line 11
    new-instance v1, Lh71/a;

    .line 12
    .line 13
    const-string v2, "Drive"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lh71/a;->e:Lh71/a;

    .line 20
    .line 21
    filled-new-array {v0, v1}, [Lh71/a;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lh71/a;->f:[Lh71/a;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lh71/a;
    .locals 1

    .line 1
    const-class v0, Lh71/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lh71/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lh71/a;
    .locals 1

    .line 1
    sget-object v0, Lh71/a;->f:[Lh71/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lh71/a;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final a(Ll2/o;)J
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p0, :cond_1

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-ne p0, v1, :cond_0

    .line 10
    .line 11
    check-cast p1, Ll2/t;

    .line 12
    .line 13
    const p0, -0x1a497052

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Lh71/m;->a:Ll2/u2;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lh71/l;

    .line 26
    .line 27
    iget-object p0, p0, Lh71/l;->b:Lh71/j;

    .line 28
    .line 29
    iget-wide v1, p0, Lh71/j;->b:J

    .line 30
    .line 31
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 32
    .line 33
    .line 34
    return-wide v1

    .line 35
    :cond_0
    const p0, -0x1a497f8a

    .line 36
    .line 37
    .line 38
    check-cast p1, Ll2/t;

    .line 39
    .line 40
    invoke-static {p0, p1, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    throw p0

    .line 45
    :cond_1
    check-cast p1, Ll2/t;

    .line 46
    .line 47
    const p0, -0x1a4977d0

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 51
    .line 52
    .line 53
    sget-object p0, Lh71/m;->a:Ll2/u2;

    .line 54
    .line 55
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Lh71/l;

    .line 60
    .line 61
    iget-object p0, p0, Lh71/l;->b:Lh71/j;

    .line 62
    .line 63
    iget-wide v1, p0, Lh71/j;->a:J

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    return-wide v1
.end method

.method public final b(Ll2/o;)J
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p0, :cond_1

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-ne p0, v1, :cond_0

    .line 10
    .line 11
    check-cast p1, Ll2/t;

    .line 12
    .line 13
    const p0, -0x7c0e89d2

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Lh71/m;->a:Ll2/u2;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lh71/l;

    .line 26
    .line 27
    iget-object p0, p0, Lh71/l;->e:Lh71/k;

    .line 28
    .line 29
    iget-wide v1, p0, Lh71/k;->d:J

    .line 30
    .line 31
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 32
    .line 33
    .line 34
    return-wide v1

    .line 35
    :cond_0
    const p0, -0x7c0e9850

    .line 36
    .line 37
    .line 38
    check-cast p1, Ll2/t;

    .line 39
    .line 40
    invoke-static {p0, p1, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    throw p0

    .line 45
    :cond_1
    check-cast p1, Ll2/t;

    .line 46
    .line 47
    const p0, -0x7c0e90f0

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 51
    .line 52
    .line 53
    sget-object p0, Lh71/m;->a:Ll2/u2;

    .line 54
    .line 55
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Lh71/l;

    .line 60
    .line 61
    iget-object p0, p0, Lh71/l;->e:Lh71/k;

    .line 62
    .line 63
    iget-wide v1, p0, Lh71/k;->c:J

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    return-wide v1
.end method

.method public final c(Ll2/o;)J
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p0, :cond_1

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-ne p0, v1, :cond_0

    .line 10
    .line 11
    check-cast p1, Ll2/t;

    .line 12
    .line 13
    const p0, 0x666efc17

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Lh71/m;->a:Ll2/u2;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lh71/l;

    .line 26
    .line 27
    iget-object p0, p0, Lh71/l;->e:Lh71/k;

    .line 28
    .line 29
    iget-wide v1, p0, Lh71/k;->f:J

    .line 30
    .line 31
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 32
    .line 33
    .line 34
    return-wide v1

    .line 35
    :cond_0
    const p0, 0x666eec82

    .line 36
    .line 37
    .line 38
    check-cast p1, Ll2/t;

    .line 39
    .line 40
    invoke-static {p0, p1, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    throw p0

    .line 45
    :cond_1
    check-cast p1, Ll2/t;

    .line 46
    .line 47
    const p0, 0x666ef3d9

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 51
    .line 52
    .line 53
    sget-object p0, Lh71/m;->a:Ll2/u2;

    .line 54
    .line 55
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Lh71/l;

    .line 60
    .line 61
    iget-object p0, p0, Lh71/l;->e:Lh71/k;

    .line 62
    .line 63
    iget-wide v1, p0, Lh71/k;->e:J

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    return-wide v1
.end method

.method public final d(Ll2/o;)J
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p0, :cond_1

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-ne p0, v1, :cond_0

    .line 10
    .line 11
    check-cast p1, Ll2/t;

    .line 12
    .line 13
    const p0, 0x7e9f77f3

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Lh71/m;->a:Ll2/u2;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lh71/l;

    .line 26
    .line 27
    iget-object p0, p0, Lh71/l;->e:Lh71/k;

    .line 28
    .line 29
    iget-wide v1, p0, Lh71/k;->b:J

    .line 30
    .line 31
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 32
    .line 33
    .line 34
    return-wide v1

    .line 35
    :cond_0
    const p0, 0x7e9f68da

    .line 36
    .line 37
    .line 38
    check-cast p1, Ll2/t;

    .line 39
    .line 40
    invoke-static {p0, p1, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    throw p0

    .line 45
    :cond_1
    check-cast p1, Ll2/t;

    .line 46
    .line 47
    const p0, 0x7e9f7035

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 51
    .line 52
    .line 53
    sget-object p0, Lh71/m;->a:Ll2/u2;

    .line 54
    .line 55
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Lh71/l;

    .line 60
    .line 61
    iget-object p0, p0, Lh71/l;->e:Lh71/k;

    .line 62
    .line 63
    iget-wide v1, p0, Lh71/k;->a:J

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    return-wide v1
.end method
