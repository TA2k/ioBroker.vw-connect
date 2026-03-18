.class public final Lm2/t;
.super Lm2/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lm2/t;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lm2/t;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, 0x0

    .line 6
    invoke-direct {v0, v3, v1, v2}, Lm2/j0;-><init>(III)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lm2/t;->c:Lm2/t;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Landroidx/collection/h;Ll2/c;Ll2/i2;Ljp/uf;Lm2/k0;)V
    .locals 7

    .line 1
    const/4 p0, 0x1

    .line 2
    invoke-virtual {p1, p0}, Landroidx/collection/h;->g(I)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    check-cast v0, Ll2/f2;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-virtual {p1, v1}, Landroidx/collection/h;->g(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    check-cast v2, Ll2/a;

    .line 14
    .line 15
    const/4 v3, 0x2

    .line 16
    invoke-virtual {p1, v3}, Landroidx/collection/h;->g(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Lm2/c;

    .line 21
    .line 22
    invoke-virtual {v0}, Ll2/f2;->i()Ll2/i2;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    if-eqz p5, :cond_0

    .line 27
    .line 28
    :try_start_0
    new-instance v4, Lvp/y1;

    .line 29
    .line 30
    const/16 v5, 0x10

    .line 31
    .line 32
    const/4 v6, 0x0

    .line 33
    invoke-direct {v4, p5, p3, v6, v5}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :catchall_0
    move-exception p0

    .line 38
    goto :goto_1

    .line 39
    :cond_0
    const/4 v4, 0x0

    .line 40
    :goto_0
    iget-object p5, p1, Lm2/c;->c:Lm2/l0;

    .line 41
    .line 42
    invoke-virtual {p5}, Lm2/l0;->f()Z

    .line 43
    .line 44
    .line 45
    move-result p5

    .line 46
    if-nez p5, :cond_1

    .line 47
    .line 48
    const-string p5, "FixupList has pending fixup operations that were not realized. Were there mismatched insertNode() and endNodeInsert() calls?"

    .line 49
    .line 50
    invoke-static {p5}, Ll2/v;->c(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    :cond_1
    iget-object p1, p1, Lm2/c;->b:Lm2/l0;

    .line 54
    .line 55
    invoke-virtual {p1, p2, v3, p4, v4}, Lm2/l0;->e(Ll2/c;Ll2/i2;Ljp/uf;Lm2/k0;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 56
    .line 57
    .line 58
    invoke-virtual {v3, p0}, Ll2/i2;->e(Z)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p3}, Ll2/i2;->d()V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v0, v2}, Ll2/f2;->c(Ll2/a;)I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    invoke-virtual {p3, v0, p0}, Ll2/i2;->z(Ll2/f2;I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p3}, Ll2/i2;->k()V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    :goto_1
    invoke-virtual {v3, v1}, Ll2/i2;->e(Z)V

    .line 79
    .line 80
    .line 81
    throw p0
.end method
