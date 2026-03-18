.class public final Landroidx/collection/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxo/f;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:I

.field public g:I

.field public h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Landroidx/collection/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(IIILg4/l0;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Landroidx/collection/h;->d:I

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    iput p1, p0, Landroidx/collection/h;->e:I

    .line 18
    iput p2, p0, Landroidx/collection/h;->f:I

    .line 19
    iput p3, p0, Landroidx/collection/h;->g:I

    .line 20
    iput-object p4, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/datastore/preferences/protobuf/k;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Landroidx/collection/h;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 4
    iput v0, p0, Landroidx/collection/h;->g:I

    .line 5
    sget-object v0, Landroidx/datastore/preferences/protobuf/a0;->a:Ljava/nio/charset/Charset;

    iput-object p1, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    iput-object p0, p1, Landroidx/datastore/preferences/protobuf/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/datastore/preferences/protobuf/k;B)V
    .locals 0

    const/4 p2, 0x2

    iput p2, p0, Landroidx/collection/h;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p2, 0x0

    .line 8
    iput p2, p0, Landroidx/collection/h;->g:I

    .line 9
    sget-object p2, Landroidx/glance/appwidget/protobuf/y;->a:Ljava/nio/charset/Charset;

    iput-object p1, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 10
    iput-object p0, p1, Landroidx/datastore/preferences/protobuf/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/crypto/tink/shaded/protobuf/j;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Landroidx/collection/h;->d:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 12
    iput v0, p0, Landroidx/collection/h;->g:I

    .line 13
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    iput-object p1, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 14
    iput-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/j;->b:Landroidx/collection/h;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;III)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Landroidx/collection/h;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    iput p2, p0, Landroidx/collection/h;->e:I

    iput p3, p0, Landroidx/collection/h;->f:I

    iput p4, p0, Landroidx/collection/h;->g:I

    return-void
.end method

.method public constructor <init>(Lm2/l0;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Landroidx/collection/h;->d:I

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    return-void
.end method

.method public static M0(I)V
    .locals 1

    .line 1
    and-int/lit8 p0, p0, 0x3

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Landroidx/datastore/preferences/protobuf/c0;

    .line 7
    .line 8
    const-string v0, "Failed to parse the message."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public static N0(I)V
    .locals 1

    .line 1
    and-int/lit8 p0, p0, 0x3

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Landroidx/glance/appwidget/protobuf/a0;

    .line 7
    .line 8
    const-string v0, "Failed to parse the message."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public static O0(I)V
    .locals 0

    .line 1
    and-int/lit8 p0, p0, 0x3

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->e()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    throw p0
.end method

.method public static P0(I)V
    .locals 1

    .line 1
    and-int/lit8 p0, p0, 0x7

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Landroidx/datastore/preferences/protobuf/c0;

    .line 7
    .line 8
    const-string v0, "Failed to parse the message."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public static Q0(I)V
    .locals 1

    .line 1
    and-int/lit8 p0, p0, 0x7

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Landroidx/glance/appwidget/protobuf/a0;

    .line 7
    .line 8
    const-string v0, "Failed to parse the message."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public static R0(I)V
    .locals 0

    .line 1
    and-int/lit8 p0, p0, 0x7

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->e()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    throw p0
.end method


# virtual methods
.method public A()I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public A0(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public B(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->q()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->q()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public B0(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public C(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->q()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->q()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public C0(Ljava/util/List;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 12
    .line 13
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 14
    .line 15
    and-int/lit8 p1, p1, 0x7

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    if-ne p1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    add-int/2addr v2, p1

    .line 30
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-lt p1, v2, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 71
    .line 72
    if-eq p1, v2, :cond_2

    .line 73
    .line 74
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 75
    .line 76
    return-void

    .line 77
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 78
    .line 79
    and-int/lit8 v1, v1, 0x7

    .line 80
    .line 81
    if-eqz v1, :cond_7

    .line 82
    .line 83
    if-ne v1, v2, :cond_6

    .line 84
    .line 85
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    add-int/2addr v2, v1

    .line 94
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-lt v1, v2, :cond_5

    .line 110
    .line 111
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    throw p0

    .line 120
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_8

    .line 136
    .line 137
    :goto_0
    return-void

    .line 138
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 143
    .line 144
    if-eq v1, v2, :cond_7

    .line 145
    .line 146
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 147
    .line 148
    return-void
.end method

.method public D(Ljava/util/List;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 12
    .line 13
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 14
    .line 15
    and-int/lit8 p1, p1, 0x7

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    if-ne p1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    add-int/2addr v2, p1

    .line 30
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-lt p1, v2, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 71
    .line 72
    if-eq p1, v2, :cond_2

    .line 73
    .line 74
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 75
    .line 76
    return-void

    .line 77
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 78
    .line 79
    and-int/lit8 v1, v1, 0x7

    .line 80
    .line 81
    if-eqz v1, :cond_7

    .line 82
    .line 83
    if-ne v1, v2, :cond_6

    .line 84
    .line 85
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    add-int/2addr v2, v1

    .line 94
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-lt v1, v2, :cond_5

    .line 110
    .line 111
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    throw p0

    .line 120
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_8

    .line 136
    .line 137
    :goto_0
    return-void

    .line 138
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 143
    .line 144
    if-eq v1, v2, :cond_7

    .line 145
    .line 146
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 147
    .line 148
    return-void
.end method

.method public D0()J
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    return-wide v0
.end method

.method public E(Landroidx/datastore/preferences/protobuf/v1;Ljava/lang/Class;Landroidx/datastore/preferences/protobuf/o;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    const/4 v1, 0x2

    .line 10
    const/4 v2, 0x5

    .line 11
    const/4 v3, 0x1

    .line 12
    const/4 v4, 0x0

    .line 13
    packed-switch p1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    :pswitch_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string p1, "unsupported field type."

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :pswitch_1
    invoke-virtual {p0, v4}, Landroidx/collection/h;->J0(I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->z()J

    .line 28
    .line 29
    .line 30
    move-result-wide p0

    .line 31
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_2
    invoke-virtual {p0, v4}, Landroidx/collection/h;->J0(I)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->y()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_3
    invoke-virtual {p0, v3}, Landroidx/collection/h;->J0(I)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->x()J

    .line 52
    .line 53
    .line 54
    move-result-wide p0

    .line 55
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_4
    invoke-virtual {p0, v2}, Landroidx/collection/h;->J0(I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->w()I

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_5
    invoke-virtual {p0, v4}, Landroidx/collection/h;->J0(I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->q()I

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    :pswitch_6
    invoke-virtual {p0, v4}, Landroidx/collection/h;->J0(I)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0

    .line 96
    :pswitch_7
    invoke-virtual {p0}, Landroidx/collection/h;->q()Landroidx/datastore/preferences/protobuf/h;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :pswitch_8
    invoke-virtual {p0, v1}, Landroidx/collection/h;->J0(I)V

    .line 102
    .line 103
    .line 104
    sget-object p1, Landroidx/datastore/preferences/protobuf/x0;->c:Landroidx/datastore/preferences/protobuf/x0;

    .line 105
    .line 106
    invoke-virtual {p1, p2}, Landroidx/datastore/preferences/protobuf/x0;->a(Ljava/lang/Class;)Landroidx/datastore/preferences/protobuf/a1;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-interface {p1}, Landroidx/datastore/preferences/protobuf/a1;->c()Landroidx/datastore/preferences/protobuf/x;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    invoke-virtual {p0, p2, p1, p3}, Landroidx/collection/h;->k(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V

    .line 115
    .line 116
    .line 117
    invoke-interface {p1, p2}, Landroidx/datastore/preferences/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    return-object p2

    .line 121
    :pswitch_9
    invoke-virtual {p0, v1}, Landroidx/collection/h;->J0(I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->B()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    return-object p0

    .line 129
    :pswitch_a
    invoke-virtual {p0, v4}, Landroidx/collection/h;->J0(I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->m()Z

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    return-object p0

    .line 141
    :pswitch_b
    invoke-virtual {p0, v2}, Landroidx/collection/h;->J0(I)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->r()I

    .line 145
    .line 146
    .line 147
    move-result p0

    .line 148
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    return-object p0

    .line 153
    :pswitch_c
    invoke-virtual {p0, v3}, Landroidx/collection/h;->J0(I)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->s()J

    .line 157
    .line 158
    .line 159
    move-result-wide p0

    .line 160
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    return-object p0

    .line 165
    :pswitch_d
    invoke-virtual {p0, v4}, Landroidx/collection/h;->J0(I)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->u()I

    .line 169
    .line 170
    .line 171
    move-result p0

    .line 172
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0

    .line 177
    :pswitch_e
    invoke-virtual {p0, v4}, Landroidx/collection/h;->J0(I)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->E()J

    .line 181
    .line 182
    .line 183
    move-result-wide p0

    .line 184
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    return-object p0

    .line 189
    :pswitch_f
    invoke-virtual {p0, v4}, Landroidx/collection/h;->J0(I)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->v()J

    .line 193
    .line 194
    .line 195
    move-result-wide p0

    .line 196
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    return-object p0

    .line 201
    :pswitch_10
    invoke-virtual {p0, v2}, Landroidx/collection/h;->J0(I)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->t()F

    .line 205
    .line 206
    .line 207
    move-result p0

    .line 208
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    return-object p0

    .line 213
    :pswitch_11
    invoke-virtual {p0, v3}, Landroidx/collection/h;->J0(I)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->p()D

    .line 217
    .line 218
    .line 219
    move-result-wide p0

    .line 220
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    return-object p0

    .line 225
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public E0(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->E()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->E()J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public F()I
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public F0(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->E()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->E()J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public G(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-eq v1, v2, :cond_3

    .line 11
    .line 12
    const/4 v2, 0x5

    .line 13
    if-ne v1, v2, :cond_2

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->r()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 38
    .line 39
    if-eq v1, v2, :cond_0

    .line 40
    .line 41
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {p0}, Landroidx/collection/h;->M0(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    add-int/2addr v1, p0

    .line 61
    :cond_4
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->r()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-lt p0, v1, :cond_4

    .line 77
    .line 78
    :goto_0
    return-void
.end method

.method public G0(Ljava/util/List;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 12
    .line 13
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 14
    .line 15
    and-int/lit8 p1, p1, 0x7

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    if-ne p1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    add-int/2addr v2, p1

    .line 30
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 31
    .line 32
    .line 33
    move-result-wide v3

    .line 34
    invoke-virtual {v1, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-lt p1, v2, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 53
    .line 54
    .line 55
    move-result-wide v2

    .line 56
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 71
    .line 72
    if-eq p1, v2, :cond_2

    .line 73
    .line 74
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 75
    .line 76
    return-void

    .line 77
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 78
    .line 79
    and-int/lit8 v1, v1, 0x7

    .line 80
    .line 81
    if-eqz v1, :cond_7

    .line 82
    .line 83
    if-ne v1, v2, :cond_6

    .line 84
    .line 85
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    add-int/2addr v2, v1

    .line 94
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 95
    .line 96
    .line 97
    move-result-wide v3

    .line 98
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-lt v1, v2, :cond_5

    .line 110
    .line 111
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    throw p0

    .line 120
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 121
    .line 122
    .line 123
    move-result-wide v1

    .line 124
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_8

    .line 136
    .line 137
    :goto_0
    return-void

    .line 138
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 143
    .line 144
    if-eq v1, v2, :cond_7

    .line 145
    .line 146
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 147
    .line 148
    return-void
.end method

.method public H(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-eq v1, v2, :cond_3

    .line 11
    .line 12
    const/4 v2, 0x5

    .line 13
    if-ne v1, v2, :cond_2

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->r()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 38
    .line 39
    if-eq v1, v2, :cond_0

    .line 40
    .line 41
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {p0}, Landroidx/collection/h;->N0(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    add-int/2addr v1, p0

    .line 61
    :cond_4
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->r()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-lt p0, v1, :cond_4

    .line 77
    .line 78
    :goto_0
    return-void
.end method

.method public H0(I)V
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Landroidx/datastore/preferences/protobuf/k;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-ne p0, p1, :cond_0

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->e()Landroidx/glance/appwidget/protobuf/a0;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    throw p0

    .line 22
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Landroidx/datastore/preferences/protobuf/k;

    .line 25
    .line 26
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-ne p0, p1, :cond_1

    .line 31
    .line 32
    return-void

    .line 33
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->e()Landroidx/datastore/preferences/protobuf/c0;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    throw p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public I(Ljava/util/List;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 6
    .line 7
    const/4 v2, 0x5

    .line 8
    const/4 v3, 0x2

    .line 9
    if-eqz v1, :cond_5

    .line 10
    .line 11
    move-object v1, p1

    .line 12
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 13
    .line 14
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 15
    .line 16
    and-int/lit8 p1, p1, 0x7

    .line 17
    .line 18
    if-eq p1, v3, :cond_3

    .line 19
    .line 20
    if-ne p1, v2, :cond_2

    .line 21
    .line 22
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_1

    .line 34
    .line 35
    goto/16 :goto_0

    .line 36
    .line 37
    :cond_1
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 42
    .line 43
    if-eq p1, v2, :cond_0

    .line 44
    .line 45
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 46
    .line 47
    return-void

    .line 48
    :cond_2
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    throw p0

    .line 53
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-static {p0}, Landroidx/collection/h;->O0(I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    add-int v4, p1, p0

    .line 65
    .line 66
    :cond_4
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    invoke-virtual {v1, p0}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    if-lt p0, v4, :cond_4

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 81
    .line 82
    and-int/lit8 v1, v1, 0x7

    .line 83
    .line 84
    if-eq v1, v3, :cond_9

    .line 85
    .line 86
    if-ne v1, v2, :cond_8

    .line 87
    .line 88
    :cond_6
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-eqz v1, :cond_7

    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 111
    .line 112
    if-eq v1, v2, :cond_6

    .line 113
    .line 114
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 115
    .line 116
    return-void

    .line 117
    :cond_8
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    throw p0

    .line 122
    :cond_9
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 123
    .line 124
    .line 125
    move-result p0

    .line 126
    invoke-static {p0}, Landroidx/collection/h;->O0(I)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 130
    .line 131
    .line 132
    move-result v1

    .line 133
    add-int/2addr v1, p0

    .line 134
    :cond_a
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 146
    .line 147
    .line 148
    move-result p0

    .line 149
    if-lt p0, v1, :cond_a

    .line 150
    .line 151
    :goto_0
    return-void
.end method

.method public I0(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    throw p0
.end method

.method public J()J
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    return-wide v0
.end method

.method public J0(I)V
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Landroidx/collection/h;->e:I

    .line 7
    .line 8
    and-int/lit8 p0, p0, 0x7

    .line 9
    .line 10
    if-ne p0, p1, :cond_0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    throw p0

    .line 18
    :pswitch_0
    iget p0, p0, Landroidx/collection/h;->e:I

    .line 19
    .line 20
    and-int/lit8 p0, p0, 0x7

    .line 21
    .line 22
    if-ne p0, p1, :cond_1

    .line 23
    .line 24
    return-void

    .line 25
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    throw p0

    .line 30
    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public K(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eq v1, v2, :cond_2

    .line 11
    .line 12
    const/4 p0, 0x2

    .line 13
    if-ne v1, p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Landroidx/collection/h;->P0(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    add-int/2addr v1, p0

    .line 27
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->s()J

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-lt p0, v1, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->s()J

    .line 51
    .line 52
    .line 53
    move-result-wide v1

    .line 54
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    :goto_0
    return-void

    .line 68
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 73
    .line 74
    if-eq v1, v2, :cond_2

    .line 75
    .line 76
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 77
    .line 78
    return-void
.end method

.method public K0(I)V
    .locals 0

    .line 1
    iget p0, p0, Landroidx/collection/h;->e:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x7

    .line 4
    .line 5
    if-ne p0, p1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    throw p0
.end method

.method public L(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eq v1, v2, :cond_2

    .line 11
    .line 12
    const/4 p0, 0x2

    .line 13
    if-ne v1, p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Landroidx/collection/h;->Q0(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    add-int/2addr v1, p0

    .line 27
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->s()J

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-lt p0, v1, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->s()J

    .line 51
    .line 52
    .line 53
    move-result-wide v1

    .line 54
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    :goto_0
    return-void

    .line 68
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 73
    .line 74
    if-eq v1, v2, :cond_2

    .line 75
    .line 76
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 77
    .line 78
    return-void
.end method

.method public L0()Z
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 12
    .line 13
    iget p0, p0, Landroidx/collection/h;->f:I

    .line 14
    .line 15
    if-ne v1, p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    invoke-virtual {v0, v1}, Landroidx/datastore/preferences/protobuf/k;->F(I)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public M(Ljava/util/List;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    const/4 v3, 0x1

    .line 9
    if-eqz v1, :cond_4

    .line 10
    .line 11
    move-object v1, p1

    .line 12
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 13
    .line 14
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 15
    .line 16
    and-int/lit8 p1, p1, 0x7

    .line 17
    .line 18
    if-eq p1, v3, :cond_2

    .line 19
    .line 20
    if-ne p1, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-static {p0}, Landroidx/collection/h;->R0(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    add-int/2addr p1, p0

    .line 34
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-lt p0, p1, :cond_0

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 54
    .line 55
    .line 56
    move-result-wide v2

    .line 57
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    if-eqz p1, :cond_3

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq p1, v2, :cond_2

    .line 74
    .line 75
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void

    .line 78
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 79
    .line 80
    and-int/lit8 v1, v1, 0x7

    .line 81
    .line 82
    if-eq v1, v3, :cond_7

    .line 83
    .line 84
    if-ne v1, v2, :cond_6

    .line 85
    .line 86
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    invoke-static {p0}, Landroidx/collection/h;->R0(I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    add-int/2addr v1, p0

    .line 98
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 99
    .line 100
    .line 101
    move-result-wide v2

    .line 102
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    if-lt p0, v1, :cond_5

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    throw p0

    .line 121
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 122
    .line 123
    .line 124
    move-result-wide v1

    .line 125
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    if-eqz v1, :cond_8

    .line 137
    .line 138
    :goto_0
    return-void

    .line 139
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 144
    .line 145
    if-eq v1, v2, :cond_7

    .line 146
    .line 147
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 148
    .line 149
    return-void
.end method

.method public N()F
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public O(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-eq v1, v2, :cond_3

    .line 11
    .line 12
    const/4 v2, 0x5

    .line 13
    if-ne v1, v2, :cond_2

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->t()F

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 38
    .line 39
    if-eq v1, v2, :cond_0

    .line 40
    .line 41
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {p0}, Landroidx/collection/h;->M0(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    add-int/2addr v1, p0

    .line 61
    :cond_4
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->t()F

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-lt p0, v1, :cond_4

    .line 77
    .line 78
    :goto_0
    return-void
.end method

.method public P(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-eq v1, v2, :cond_3

    .line 11
    .line 12
    const/4 v2, 0x5

    .line 13
    if-ne v1, v2, :cond_2

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->t()F

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 38
    .line 39
    if-eq v1, v2, :cond_0

    .line 40
    .line 41
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {p0}, Landroidx/collection/h;->N0(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    add-int/2addr v1, p0

    .line 61
    :cond_4
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->t()F

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-lt p0, v1, :cond_4

    .line 77
    .line 78
    :goto_0
    return-void
.end method

.method public Q(Ljava/util/List;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/t;

    .line 6
    .line 7
    const/4 v2, 0x5

    .line 8
    const/4 v3, 0x2

    .line 9
    if-eqz v1, :cond_5

    .line 10
    .line 11
    move-object v1, p1

    .line 12
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/t;

    .line 13
    .line 14
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 15
    .line 16
    and-int/lit8 p1, p1, 0x7

    .line 17
    .line 18
    if-eq p1, v3, :cond_3

    .line 19
    .line 20
    if-ne p1, v2, :cond_2

    .line 21
    .line 22
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/t;->e(F)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    if-eqz p1, :cond_1

    .line 38
    .line 39
    goto/16 :goto_0

    .line 40
    .line 41
    :cond_1
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 46
    .line 47
    if-eq p1, v2, :cond_0

    .line 48
    .line 49
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 50
    .line 51
    return-void

    .line 52
    :cond_2
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    throw p0

    .line 57
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    invoke-static {p0}, Landroidx/collection/h;->O0(I)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    add-int v4, p1, p0

    .line 69
    .line 70
    :cond_4
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    invoke-virtual {v1, p0}, Lcom/google/crypto/tink/shaded/protobuf/t;->e(F)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    if-lt p0, v4, :cond_4

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 89
    .line 90
    and-int/lit8 v1, v1, 0x7

    .line 91
    .line 92
    if-eq v1, v3, :cond_9

    .line 93
    .line 94
    if-ne v1, v2, :cond_8

    .line 95
    .line 96
    :cond_6
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-eqz v1, :cond_7

    .line 116
    .line 117
    goto :goto_0

    .line 118
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 123
    .line 124
    if-eq v1, v2, :cond_6

    .line 125
    .line 126
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 127
    .line 128
    return-void

    .line 129
    :cond_8
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    throw p0

    .line 134
    :cond_9
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    invoke-static {p0}, Landroidx/collection/h;->O0(I)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    add-int/2addr v1, p0

    .line 146
    :cond_a
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    if-lt p0, v1, :cond_a

    .line 166
    .line 167
    :goto_0
    return-void
.end method

.method public R(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Landroidx/collection/h;->f:I

    .line 2
    .line 3
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 4
    .line 5
    ushr-int/lit8 v1, v1, 0x3

    .line 6
    .line 7
    shl-int/lit8 v1, v1, 0x3

    .line 8
    .line 9
    or-int/lit8 v1, v1, 0x4

    .line 10
    .line 11
    iput v1, p0, Landroidx/collection/h;->f:I

    .line 12
    .line 13
    :try_start_0
    invoke-interface {p1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->c()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-interface {p1, v1, p0, p2}, Lcom/google/crypto/tink/shaded/protobuf/a1;->f(Ljava/lang/Object;Landroidx/collection/h;Lcom/google/crypto/tink/shaded/protobuf/p;)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 24
    .line 25
    iget p2, p0, Landroidx/collection/h;->f:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    if-ne p1, p2, :cond_0

    .line 28
    .line 29
    iput v0, p0, Landroidx/collection/h;->f:I

    .line 30
    .line 31
    return-object v1

    .line 32
    :cond_0
    :try_start_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->e()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 37
    :catchall_0
    move-exception p1

    .line 38
    iput v0, p0, Landroidx/collection/h;->f:I

    .line 39
    .line 40
    throw p1
.end method

.method public S(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;
    .locals 1

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Landroidx/collection/h;->R(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public T(Ljava/util/List;Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v2, v1, 0x7

    .line 8
    .line 9
    const/4 v3, 0x3

    .line 10
    if-ne v2, v3, :cond_3

    .line 11
    .line 12
    :cond_0
    invoke-virtual {p0, p2, p3}, Landroidx/collection/h;->R(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-interface {p1, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-nez v2, :cond_2

    .line 24
    .line 25
    iget v2, p0, Landroidx/collection/h;->g:I

    .line 26
    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eq v2, v1, :cond_0

    .line 35
    .line 36
    iput v2, p0, Landroidx/collection/h;->g:I

    .line 37
    .line 38
    :cond_2
    :goto_0
    return-void

    .line 39
    :cond_3
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    throw p0
.end method

.method public U()I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public V(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->u()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->u()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public W(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->u()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->u()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public X(Ljava/util/List;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 12
    .line 13
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 14
    .line 15
    and-int/lit8 p1, p1, 0x7

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    if-ne p1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    add-int/2addr v2, p1

    .line 30
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-lt p1, v2, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 71
    .line 72
    if-eq p1, v2, :cond_2

    .line 73
    .line 74
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 75
    .line 76
    return-void

    .line 77
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 78
    .line 79
    and-int/lit8 v1, v1, 0x7

    .line 80
    .line 81
    if-eqz v1, :cond_7

    .line 82
    .line 83
    if-ne v1, v2, :cond_6

    .line 84
    .line 85
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    add-int/2addr v2, v1

    .line 94
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-lt v1, v2, :cond_5

    .line 110
    .line 111
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    throw p0

    .line 120
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_8

    .line 136
    .line 137
    :goto_0
    return-void

    .line 138
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 143
    .line 144
    if-eq v1, v2, :cond_7

    .line 145
    .line 146
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 147
    .line 148
    return-void
.end method

.method public Y()J
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    return-wide v0
.end method

.method public Z(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->v()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->v()J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public a(Lna/g;)V
    .locals 6

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, [Ljava/lang/Object;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->f:I

    .line 6
    .line 7
    aput-object p1, v0, v1

    .line 8
    .line 9
    add-int/lit8 v1, v1, 0x1

    .line 10
    .line 11
    iget p1, p0, Landroidx/collection/h;->g:I

    .line 12
    .line 13
    and-int/2addr p1, v1

    .line 14
    iput p1, p0, Landroidx/collection/h;->f:I

    .line 15
    .line 16
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 17
    .line 18
    if-ne p1, v1, :cond_1

    .line 19
    .line 20
    array-length p1, v0

    .line 21
    sub-int v2, p1, v1

    .line 22
    .line 23
    shl-int/lit8 v3, p1, 0x1

    .line 24
    .line 25
    if-ltz v3, :cond_0

    .line 26
    .line 27
    new-array v4, v3, [Ljava/lang/Object;

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-static {v5, v1, p1, v0, v4}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, [Ljava/lang/Object;

    .line 36
    .line 37
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 38
    .line 39
    invoke-static {v2, v5, v1, v0, v4}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iput-object v4, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 43
    .line 44
    iput v5, p0, Landroidx/collection/h;->e:I

    .line 45
    .line 46
    iput p1, p0, Landroidx/collection/h;->f:I

    .line 47
    .line 48
    add-int/lit8 v3, v3, -0x1

    .line 49
    .line 50
    iput v3, p0, Landroidx/collection/h;->g:I

    .line 51
    .line 52
    return-void

    .line 53
    :cond_0
    new-instance p0, Ljava/lang/RuntimeException;

    .line 54
    .line 55
    const-string p1, "Max array capacity exceeded"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_1
    return-void
.end method

.method public a0(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->v()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->v()J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public b(I)Le2/r;
    .locals 3

    .line 1
    new-instance v0, Le2/r;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lg4/l0;

    .line 6
    .line 7
    invoke-static {p0, p1}, Lkp/t;->i(Lg4/l0;I)Lr4/j;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-wide/16 v1, 0x1

    .line 12
    .line 13
    invoke-direct {v0, p0, p1, v1, v2}, Le2/r;-><init>(Lr4/j;IJ)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public b0(Ljava/util/List;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 12
    .line 13
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 14
    .line 15
    and-int/lit8 p1, p1, 0x7

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    if-ne p1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    add-int/2addr v2, p1

    .line 30
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 31
    .line 32
    .line 33
    move-result-wide v3

    .line 34
    invoke-virtual {v1, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-lt p1, v2, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 53
    .line 54
    .line 55
    move-result-wide v2

    .line 56
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 71
    .line 72
    if-eq p1, v2, :cond_2

    .line 73
    .line 74
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 75
    .line 76
    return-void

    .line 77
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 78
    .line 79
    and-int/lit8 v1, v1, 0x7

    .line 80
    .line 81
    if-eqz v1, :cond_7

    .line 82
    .line 83
    if-ne v1, v2, :cond_6

    .line 84
    .line 85
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    add-int/2addr v2, v1

    .line 94
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 95
    .line 96
    .line 97
    move-result-wide v3

    .line 98
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-lt v1, v2, :cond_5

    .line 110
    .line 111
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    throw p0

    .line 120
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 121
    .line 122
    .line 123
    move-result-wide v1

    .line 124
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_8

    .line 136
    .line 137
    :goto_0
    return-void

    .line 138
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 143
    .line 144
    if-eq v1, v2, :cond_7

    .line 145
    .line 146
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 147
    .line 148
    return-void
.end method

.method public c(Lj51/b;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    iget v2, p0, Landroidx/collection/h;->f:I

    .line 8
    .line 9
    iget p0, p0, Landroidx/collection/h;->g:I

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const-string v3, "digitalKeyId"

    .line 15
    .line 16
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object p1, p1, Lj51/b;->a:Lxy0/x;

    .line 20
    .line 21
    new-instance v3, Lk51/d;

    .line 22
    .line 23
    invoke-direct {v3, v0, v1, v2, p0}, Lk51/d;-><init>(Ljava/lang/String;III)V

    .line 24
    .line 25
    .line 26
    check-cast p1, Lxy0/w;

    .line 27
    .line 28
    invoke-virtual {p1, v3}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public c0(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget v2, v0, Lcom/google/crypto/tink/shaded/protobuf/j;->a:I

    .line 10
    .line 11
    const/16 v3, 0x64

    .line 12
    .line 13
    if-ge v2, v3, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/j;->e(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-interface {p1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->c()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    iget v3, v0, Lcom/google/crypto/tink/shaded/protobuf/j;->a:I

    .line 24
    .line 25
    add-int/lit8 v3, v3, 0x1

    .line 26
    .line 27
    iput v3, v0, Lcom/google/crypto/tink/shaded/protobuf/j;->a:I

    .line 28
    .line 29
    invoke-interface {p1, v2, p0, p2}, Lcom/google/crypto/tink/shaded/protobuf/a1;->f(Ljava/lang/Object;Landroidx/collection/h;Lcom/google/crypto/tink/shaded/protobuf/p;)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget p0, v0, Lcom/google/crypto/tink/shaded/protobuf/j;->h:I

    .line 36
    .line 37
    if-nez p0, :cond_0

    .line 38
    .line 39
    iget p0, v0, Lcom/google/crypto/tink/shaded/protobuf/j;->a:I

    .line 40
    .line 41
    add-int/lit8 p0, p0, -0x1

    .line 42
    .line 43
    iput p0, v0, Lcom/google/crypto/tink/shaded/protobuf/j;->a:I

    .line 44
    .line 45
    iput v1, v0, Lcom/google/crypto/tink/shaded/protobuf/j;->i:I

    .line 46
    .line 47
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->m()V

    .line 48
    .line 49
    .line 50
    return-object v2

    .line 51
    :cond_0
    new-instance p0, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 52
    .line 53
    const-string p1, "Protocol message end-group tag did not match expected tag."

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_1
    new-instance p0, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 60
    .line 61
    const-string p1, "Protocol message had too many levels of nesting.  May be malicious.  Use CodedInputStream.setRecursionLimit() to increase the depth limit."

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0
.end method

.method public d()I
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/h;->g:I

    .line 2
    .line 3
    iget p0, p0, Landroidx/collection/h;->f:I

    .line 4
    .line 5
    sub-int/2addr v0, p0

    .line 6
    return v0
.end method

.method public d0(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Landroidx/collection/h;->c0(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public e()I
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/h;->g:I

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iput v0, p0, Landroidx/collection/h;->e:I

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iput v0, p0, Landroidx/collection/h;->g:I

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 19
    .line 20
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iput v0, p0, Landroidx/collection/h;->e:I

    .line 25
    .line 26
    :goto_0
    iget v0, p0, Landroidx/collection/h;->e:I

    .line 27
    .line 28
    if-eqz v0, :cond_2

    .line 29
    .line 30
    iget p0, p0, Landroidx/collection/h;->f:I

    .line 31
    .line 32
    if-ne v0, p0, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    ushr-int/lit8 p0, v0, 0x3

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    :goto_1
    const p0, 0x7fffffff

    .line 39
    .line 40
    .line 41
    :goto_2
    return p0

    .line 42
    :pswitch_0
    iget v0, p0, Landroidx/collection/h;->g:I

    .line 43
    .line 44
    if-eqz v0, :cond_3

    .line 45
    .line 46
    iput v0, p0, Landroidx/collection/h;->e:I

    .line 47
    .line 48
    const/4 v0, 0x0

    .line 49
    iput v0, p0, Landroidx/collection/h;->g:I

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_3
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 55
    .line 56
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iput v0, p0, Landroidx/collection/h;->e:I

    .line 61
    .line 62
    :goto_3
    iget v0, p0, Landroidx/collection/h;->e:I

    .line 63
    .line 64
    if-eqz v0, :cond_5

    .line 65
    .line 66
    iget p0, p0, Landroidx/collection/h;->f:I

    .line 67
    .line 68
    if-ne v0, p0, :cond_4

    .line 69
    .line 70
    goto :goto_4

    .line 71
    :cond_4
    ushr-int/lit8 p0, v0, 0x3

    .line 72
    .line 73
    goto :goto_5

    .line 74
    :cond_5
    :goto_4
    const p0, 0x7fffffff

    .line 75
    .line 76
    .line 77
    :goto_5
    return p0

    .line 78
    :pswitch_1
    iget v0, p0, Landroidx/collection/h;->g:I

    .line 79
    .line 80
    if-eqz v0, :cond_6

    .line 81
    .line 82
    iput v0, p0, Landroidx/collection/h;->e:I

    .line 83
    .line 84
    const/4 v0, 0x0

    .line 85
    iput v0, p0, Landroidx/collection/h;->g:I

    .line 86
    .line 87
    goto :goto_6

    .line 88
    :cond_6
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 91
    .line 92
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    iput v0, p0, Landroidx/collection/h;->e:I

    .line 97
    .line 98
    :goto_6
    iget v0, p0, Landroidx/collection/h;->e:I

    .line 99
    .line 100
    if-eqz v0, :cond_8

    .line 101
    .line 102
    iget p0, p0, Landroidx/collection/h;->f:I

    .line 103
    .line 104
    if-ne v0, p0, :cond_7

    .line 105
    .line 106
    goto :goto_7

    .line 107
    :cond_7
    ushr-int/lit8 p0, v0, 0x3

    .line 108
    .line 109
    goto :goto_8

    .line 110
    :cond_8
    :goto_7
    const p0, 0x7fffffff

    .line 111
    .line 112
    .line 113
    :goto_8
    return p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public e0()I
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public f(I)I
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lm2/l0;

    .line 4
    .line 5
    iget-object v0, v0, Lm2/l0;->d:[I

    .line 6
    .line 7
    iget p0, p0, Landroidx/collection/h;->f:I

    .line 8
    .line 9
    add-int/2addr p0, p1

    .line 10
    aget p0, v0, p0

    .line 11
    .line 12
    return p0
.end method

.method public f0(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-eq v1, v2, :cond_3

    .line 11
    .line 12
    const/4 v2, 0x5

    .line 13
    if-ne v1, v2, :cond_2

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->w()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 38
    .line 39
    if-eq v1, v2, :cond_0

    .line 40
    .line 41
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {p0}, Landroidx/collection/h;->M0(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    add-int/2addr v1, p0

    .line 61
    :cond_4
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->w()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-lt p0, v1, :cond_4

    .line 77
    .line 78
    :goto_0
    return-void
.end method

.method public g(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lm2/l0;

    .line 4
    .line 5
    iget-object v0, v0, Lm2/l0;->f:[Ljava/lang/Object;

    .line 6
    .line 7
    iget p0, p0, Landroidx/collection/h;->g:I

    .line 8
    .line 9
    add-int/2addr p0, p1

    .line 10
    aget-object p0, v0, p0

    .line 11
    .line 12
    return-object p0
.end method

.method public g0(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-eq v1, v2, :cond_3

    .line 11
    .line 12
    const/4 v2, 0x5

    .line 13
    if-ne v1, v2, :cond_2

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->w()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 38
    .line 39
    if-eq v1, v2, :cond_0

    .line 40
    .line 41
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {p0}, Landroidx/collection/h;->N0(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    add-int/2addr v1, p0

    .line 61
    :cond_4
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->w()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-lt p0, v1, :cond_4

    .line 77
    .line 78
    :goto_0
    return-void
.end method

.method public h()I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/collection/h;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public h0(Ljava/util/List;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 6
    .line 7
    const/4 v2, 0x5

    .line 8
    const/4 v3, 0x2

    .line 9
    if-eqz v1, :cond_5

    .line 10
    .line 11
    move-object v1, p1

    .line 12
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 13
    .line 14
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 15
    .line 16
    and-int/lit8 p1, p1, 0x7

    .line 17
    .line 18
    if-eq p1, v3, :cond_3

    .line 19
    .line 20
    if-ne p1, v2, :cond_2

    .line 21
    .line 22
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_1

    .line 34
    .line 35
    goto/16 :goto_0

    .line 36
    .line 37
    :cond_1
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 42
    .line 43
    if-eq p1, v2, :cond_0

    .line 44
    .line 45
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 46
    .line 47
    return-void

    .line 48
    :cond_2
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    throw p0

    .line 53
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-static {p0}, Landroidx/collection/h;->O0(I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    add-int v4, p1, p0

    .line 65
    .line 66
    :cond_4
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    invoke-virtual {v1, p0}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    if-lt p0, v4, :cond_4

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 81
    .line 82
    and-int/lit8 v1, v1, 0x7

    .line 83
    .line 84
    if-eq v1, v3, :cond_9

    .line 85
    .line 86
    if-ne v1, v2, :cond_8

    .line 87
    .line 88
    :cond_6
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-eqz v1, :cond_7

    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 111
    .line 112
    if-eq v1, v2, :cond_6

    .line 113
    .line 114
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 115
    .line 116
    return-void

    .line 117
    :cond_8
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    throw p0

    .line 122
    :cond_9
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 123
    .line 124
    .line 125
    move-result p0

    .line 126
    invoke-static {p0}, Landroidx/collection/h;->O0(I)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 130
    .line 131
    .line 132
    move-result v1

    .line 133
    add-int/2addr v1, p0

    .line 134
    :cond_a
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->g()I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 146
    .line 147
    .line 148
    move-result p0

    .line 149
    if-lt p0, v1, :cond_a

    .line 150
    .line 151
    :goto_0
    return-void
.end method

.method public i(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V
    .locals 2

    .line 1
    iget v0, p0, Landroidx/collection/h;->f:I

    .line 2
    .line 3
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 4
    .line 5
    ushr-int/lit8 v1, v1, 0x3

    .line 6
    .line 7
    shl-int/lit8 v1, v1, 0x3

    .line 8
    .line 9
    or-int/lit8 v1, v1, 0x4

    .line 10
    .line 11
    iput v1, p0, Landroidx/collection/h;->f:I

    .line 12
    .line 13
    :try_start_0
    invoke-interface {p2, p1, p0, p3}, Landroidx/datastore/preferences/protobuf/a1;->i(Ljava/lang/Object;Landroidx/collection/h;Landroidx/datastore/preferences/protobuf/o;)V

    .line 14
    .line 15
    .line 16
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 17
    .line 18
    iget p2, p0, Landroidx/collection/h;->f:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    if-ne p1, p2, :cond_0

    .line 21
    .line 22
    iput v0, p0, Landroidx/collection/h;->f:I

    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    :try_start_1
    new-instance p1, Landroidx/datastore/preferences/protobuf/c0;

    .line 26
    .line 27
    const-string p2, "Failed to parse the message."

    .line 28
    .line 29
    invoke-direct {p1, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    :catchall_0
    move-exception p1

    .line 34
    iput v0, p0, Landroidx/collection/h;->f:I

    .line 35
    .line 36
    throw p1
.end method

.method public i0()J
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    return-wide v0
.end method

.method public j(Ljava/lang/Object;Landroidx/glance/appwidget/protobuf/v0;Landroidx/glance/appwidget/protobuf/m;)V
    .locals 2

    .line 1
    iget v0, p0, Landroidx/collection/h;->f:I

    .line 2
    .line 3
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 4
    .line 5
    ushr-int/lit8 v1, v1, 0x3

    .line 6
    .line 7
    shl-int/lit8 v1, v1, 0x3

    .line 8
    .line 9
    or-int/lit8 v1, v1, 0x4

    .line 10
    .line 11
    iput v1, p0, Landroidx/collection/h;->f:I

    .line 12
    .line 13
    :try_start_0
    invoke-interface {p2, p1, p0, p3}, Landroidx/glance/appwidget/protobuf/v0;->h(Ljava/lang/Object;Landroidx/collection/h;Landroidx/glance/appwidget/protobuf/m;)V

    .line 14
    .line 15
    .line 16
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 17
    .line 18
    iget p2, p0, Landroidx/collection/h;->f:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    if-ne p1, p2, :cond_0

    .line 21
    .line 22
    iput v0, p0, Landroidx/collection/h;->f:I

    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    :try_start_1
    new-instance p1, Landroidx/glance/appwidget/protobuf/a0;

    .line 26
    .line 27
    const-string p2, "Failed to parse the message."

    .line 28
    .line 29
    invoke-direct {p1, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    :catchall_0
    move-exception p1

    .line 34
    iput v0, p0, Landroidx/collection/h;->f:I

    .line 35
    .line 36
    throw p1
.end method

.method public j0(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eq v1, v2, :cond_2

    .line 11
    .line 12
    const/4 p0, 0x2

    .line 13
    if-ne v1, p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Landroidx/collection/h;->P0(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    add-int/2addr v1, p0

    .line 27
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->x()J

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-lt p0, v1, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->x()J

    .line 51
    .line 52
    .line 53
    move-result-wide v1

    .line 54
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    :goto_0
    return-void

    .line 68
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 73
    .line 74
    if-eq v1, v2, :cond_2

    .line 75
    .line 76
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 77
    .line 78
    return-void
.end method

.method public k(Ljava/lang/Object;Landroidx/datastore/preferences/protobuf/a1;Landroidx/datastore/preferences/protobuf/o;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget v2, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 10
    .line 11
    const/16 v3, 0x64

    .line 12
    .line 13
    if-ge v2, v3, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Landroidx/datastore/preferences/protobuf/k;->l(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iget v2, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 20
    .line 21
    add-int/lit8 v2, v2, 0x1

    .line 22
    .line 23
    iput v2, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 24
    .line 25
    invoke-interface {p2, p1, p0, p3}, Landroidx/datastore/preferences/protobuf/a1;->i(Ljava/lang/Object;Landroidx/collection/h;Landroidx/datastore/preferences/protobuf/o;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    invoke-virtual {v0, p0}, Landroidx/datastore/preferences/protobuf/k;->a(I)V

    .line 30
    .line 31
    .line 32
    iget p0, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 33
    .line 34
    add-int/lit8 p0, p0, -0x1

    .line 35
    .line 36
    iput p0, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Landroidx/datastore/preferences/protobuf/k;->k(I)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    new-instance p0, Landroidx/datastore/preferences/protobuf/c0;

    .line 43
    .line 44
    const-string p1, "Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit."

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0
.end method

.method public k0(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eq v1, v2, :cond_2

    .line 11
    .line 12
    const/4 p0, 0x2

    .line 13
    if-ne v1, p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Landroidx/collection/h;->Q0(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    add-int/2addr v1, p0

    .line 27
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->x()J

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-lt p0, v1, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->x()J

    .line 51
    .line 52
    .line 53
    move-result-wide v1

    .line 54
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    :goto_0
    return-void

    .line 68
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 73
    .line 74
    if-eq v1, v2, :cond_2

    .line 75
    .line 76
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 77
    .line 78
    return-void
.end method

.method public l(Ljava/lang/Object;Landroidx/glance/appwidget/protobuf/v0;Landroidx/glance/appwidget/protobuf/m;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget v2, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 10
    .line 11
    const/16 v3, 0x64

    .line 12
    .line 13
    if-ge v2, v3, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Landroidx/datastore/preferences/protobuf/k;->l(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iget v2, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 20
    .line 21
    add-int/lit8 v2, v2, 0x1

    .line 22
    .line 23
    iput v2, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 24
    .line 25
    invoke-interface {p2, p1, p0, p3}, Landroidx/glance/appwidget/protobuf/v0;->h(Ljava/lang/Object;Landroidx/collection/h;Landroidx/glance/appwidget/protobuf/m;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    invoke-virtual {v0, p0}, Landroidx/datastore/preferences/protobuf/k;->a(I)V

    .line 30
    .line 31
    .line 32
    iget p0, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 33
    .line 34
    add-int/lit8 p0, p0, -0x1

    .line 35
    .line 36
    iput p0, v0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Landroidx/datastore/preferences/protobuf/k;->k(I)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    new-instance p0, Landroidx/glance/appwidget/protobuf/a0;

    .line 43
    .line 44
    const-string p1, "Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit."

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0
.end method

.method public l0(Ljava/util/List;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    const/4 v3, 0x1

    .line 9
    if-eqz v1, :cond_4

    .line 10
    .line 11
    move-object v1, p1

    .line 12
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 13
    .line 14
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 15
    .line 16
    and-int/lit8 p1, p1, 0x7

    .line 17
    .line 18
    if-eq p1, v3, :cond_2

    .line 19
    .line 20
    if-ne p1, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-static {p0}, Landroidx/collection/h;->R0(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    add-int/2addr p1, p0

    .line 34
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-lt p0, p1, :cond_0

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 54
    .line 55
    .line 56
    move-result-wide v2

    .line 57
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    if-eqz p1, :cond_3

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq p1, v2, :cond_2

    .line 74
    .line 75
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void

    .line 78
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 79
    .line 80
    and-int/lit8 v1, v1, 0x7

    .line 81
    .line 82
    if-eq v1, v3, :cond_7

    .line 83
    .line 84
    if-ne v1, v2, :cond_6

    .line 85
    .line 86
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    invoke-static {p0}, Landroidx/collection/h;->R0(I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    add-int/2addr v1, p0

    .line 98
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 99
    .line 100
    .line 101
    move-result-wide v2

    .line 102
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    if-lt p0, v1, :cond_5

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    throw p0

    .line 121
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 122
    .line 123
    .line 124
    move-result-wide v1

    .line 125
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    if-eqz v1, :cond_8

    .line 137
    .line 138
    :goto_0
    return-void

    .line 139
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 144
    .line 145
    if-eq v1, v2, :cond_7

    .line 146
    .line 147
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 148
    .line 149
    return-void
.end method

.method public m()Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->f()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public m0()I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public n(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->m()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->m()Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public n0(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->y()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->y()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public o(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->m()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->m()Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public o0(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->y()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->y()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public p(Ljava/util/List;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/e;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/e;

    .line 12
    .line 13
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 14
    .line 15
    and-int/lit8 p1, p1, 0x7

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    if-ne p1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    add-int/2addr v2, p1

    .line 30
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->f()Z

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/e;->e(Z)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-lt p1, v2, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->f()Z

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/e;->e(Z)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 71
    .line 72
    if-eq p1, v2, :cond_2

    .line 73
    .line 74
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 75
    .line 76
    return-void

    .line 77
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 78
    .line 79
    and-int/lit8 v1, v1, 0x7

    .line 80
    .line 81
    if-eqz v1, :cond_7

    .line 82
    .line 83
    if-ne v1, v2, :cond_6

    .line 84
    .line 85
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    add-int/2addr v2, v1

    .line 94
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->f()Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-lt v1, v2, :cond_5

    .line 110
    .line 111
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    throw p0

    .line 120
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->f()Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_8

    .line 136
    .line 137
    :goto_0
    return-void

    .line 138
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 143
    .line 144
    if-eq v1, v2, :cond_7

    .line 145
    .line 146
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 147
    .line 148
    return-void
.end method

.method public p0(Ljava/util/List;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 12
    .line 13
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 14
    .line 15
    and-int/lit8 p1, p1, 0x7

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    if-ne p1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    add-int/2addr v2, p1

    .line 30
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    invoke-static {p1}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-lt p1, v2, :cond_0

    .line 46
    .line 47
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    invoke-static {p1}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    invoke-virtual {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-eqz p1, :cond_3

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 79
    .line 80
    if-eq p1, v2, :cond_2

    .line 81
    .line 82
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 83
    .line 84
    return-void

    .line 85
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 86
    .line 87
    and-int/lit8 v1, v1, 0x7

    .line 88
    .line 89
    if-eqz v1, :cond_7

    .line 90
    .line 91
    if-ne v1, v2, :cond_6

    .line 92
    .line 93
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    add-int/2addr v2, v1

    .line 102
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    invoke-static {v1}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    if-lt v1, v2, :cond_5

    .line 122
    .line 123
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 124
    .line 125
    .line 126
    return-void

    .line 127
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    throw p0

    .line 132
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    invoke-static {v1}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-eqz v1, :cond_8

    .line 152
    .line 153
    :goto_0
    return-void

    .line 154
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 159
    .line 160
    if-eq v1, v2, :cond_7

    .line 161
    .line 162
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 163
    .line 164
    return-void
.end method

.method public q()Landroidx/datastore/preferences/protobuf/h;
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->J0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroidx/datastore/preferences/protobuf/k;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/k;->n()Landroidx/datastore/preferences/protobuf/h;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public q0()J
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    invoke-static {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    return-wide v0
.end method

.method public r()Landroidx/glance/appwidget/protobuf/g;
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->J0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroidx/datastore/preferences/protobuf/k;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/k;->o()Landroidx/glance/appwidget/protobuf/g;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public r0(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->z()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->z()J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public s()Lcom/google/crypto/tink/shaded/protobuf/h;
    .locals 4

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->c:[B

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-lez v1, :cond_0

    .line 16
    .line 17
    iget v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->d:I

    .line 18
    .line 19
    iget v3, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 20
    .line 21
    sub-int/2addr v2, v3

    .line 22
    if-gt v1, v2, :cond_0

    .line 23
    .line 24
    invoke-static {v0, v3, v1}, Lcom/google/crypto/tink/shaded/protobuf/i;->g([BII)Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iget v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 29
    .line 30
    add-int/2addr v2, v1

    .line 31
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 32
    .line 33
    return-object v0

    .line 34
    :cond_0
    if-nez v1, :cond_1

    .line 35
    .line 36
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/i;->e:Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_1
    if-lez v1, :cond_2

    .line 40
    .line 41
    iget v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->d:I

    .line 42
    .line 43
    iget v3, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 44
    .line 45
    sub-int/2addr v2, v3

    .line 46
    if-gt v1, v2, :cond_2

    .line 47
    .line 48
    add-int/2addr v1, v3

    .line 49
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 50
    .line 51
    invoke-static {v0, v3, v1}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    goto :goto_0

    .line 56
    :cond_2
    if-gtz v1, :cond_4

    .line 57
    .line 58
    if-nez v1, :cond_3

    .line 59
    .line 60
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/b0;->b:[B

    .line 61
    .line 62
    :goto_0
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/i;->e:Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 63
    .line 64
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 65
    .line 66
    invoke-direct {v0, p0}, Lcom/google/crypto/tink/shaded/protobuf/h;-><init>([B)V

    .line 67
    .line 68
    .line 69
    return-object v0

    .line 70
    :cond_3
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    throw p0

    .line 75
    :cond_4
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    throw p0
.end method

.method public s0(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-ne v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v1

    .line 23
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->z()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-lt v1, v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v2}, Landroidx/collection/h;->H0(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->z()J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void
.end method

.method public t(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-ne v1, v2, :cond_2

    .line 11
    .line 12
    :cond_0
    invoke-virtual {p0}, Landroidx/collection/h;->q()Landroidx/datastore/preferences/protobuf/h;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 31
    .line 32
    if-eq v1, v2, :cond_0

    .line 33
    .line 34
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 35
    .line 36
    return-void

    .line 37
    :cond_2
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    throw p0
.end method

.method public t0(Ljava/util/List;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 12
    .line 13
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 14
    .line 15
    and-int/lit8 p1, p1, 0x7

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    if-ne p1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    add-int/2addr v2, p1

    .line 30
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 31
    .line 32
    .line 33
    move-result-wide v3

    .line 34
    invoke-static {v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 35
    .line 36
    .line 37
    move-result-wide v3

    .line 38
    invoke-virtual {v1, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-lt p1, v2, :cond_0

    .line 46
    .line 47
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 57
    .line 58
    .line 59
    move-result-wide v2

    .line 60
    invoke-static {v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 61
    .line 62
    .line 63
    move-result-wide v2

    .line 64
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-eqz p1, :cond_3

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 79
    .line 80
    if-eq p1, v2, :cond_2

    .line 81
    .line 82
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 83
    .line 84
    return-void

    .line 85
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 86
    .line 87
    and-int/lit8 v1, v1, 0x7

    .line 88
    .line 89
    if-eqz v1, :cond_7

    .line 90
    .line 91
    if-ne v1, v2, :cond_6

    .line 92
    .line 93
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    add-int/2addr v2, v1

    .line 102
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 103
    .line 104
    .line 105
    move-result-wide v3

    .line 106
    invoke-static {v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 107
    .line 108
    .line 109
    move-result-wide v3

    .line 110
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    if-lt v1, v2, :cond_5

    .line 122
    .line 123
    invoke-virtual {p0, v2}, Landroidx/collection/h;->I0(I)V

    .line 124
    .line 125
    .line 126
    return-void

    .line 127
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    throw p0

    .line 132
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->j()J

    .line 133
    .line 134
    .line 135
    move-result-wide v1

    .line 136
    invoke-static {v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 137
    .line 138
    .line 139
    move-result-wide v1

    .line 140
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-eqz v1, :cond_8

    .line 152
    .line 153
    :goto_0
    return-void

    .line 154
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 159
    .line 160
    if-eq v1, v2, :cond_7

    .line 161
    .line 162
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 163
    .line 164
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Landroidx/collection/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    const-string p0, ""

    .line 12
    .line 13
    return-object p0

    .line 14
    :pswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v1, "SelectionInfo(id=1, range=("

    .line 17
    .line 18
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const/16 v2, 0x2d

    .line 27
    .line 28
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    iget-object v3, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v3, Lg4/l0;

    .line 34
    .line 35
    invoke-static {v3, v1}, Lkp/t;->i(Lg4/l0;I)Lr4/j;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const/16 v1, 0x2c

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget v1, p0, Landroidx/collection/h;->f:I

    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-static {v3, v1}, Lkp/t;->i(Lg4/l0;I)Lr4/j;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, "), prevOffset="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget p0, p0, Landroidx/collection/h;->g:I

    .line 68
    .line 69
    const/16 v1, 0x29

    .line 70
    .line 71
    invoke-static {v0, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public u(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-ne v1, v2, :cond_2

    .line 11
    .line 12
    :cond_0
    invoke-virtual {p0}, Landroidx/collection/h;->r()Landroidx/glance/appwidget/protobuf/g;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 31
    .line 32
    if-eq v1, v2, :cond_0

    .line 33
    .line 34
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 35
    .line 36
    return-void

    .line 37
    :cond_2
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    throw p0
.end method

.method public u0()Ljava/lang/String;
    .locals 5

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-lez v0, :cond_0

    .line 14
    .line 15
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->d:I

    .line 16
    .line 17
    iget v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    if-gt v0, v1, :cond_0

    .line 21
    .line 22
    new-instance v1, Ljava/lang/String;

    .line 23
    .line 24
    iget-object v3, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->c:[B

    .line 25
    .line 26
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 27
    .line 28
    invoke-direct {v1, v3, v2, v0, v4}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 29
    .line 30
    .line 31
    iget v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 32
    .line 33
    add-int/2addr v2, v0

    .line 34
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 35
    .line 36
    return-object v1

    .line 37
    :cond_0
    if-nez v0, :cond_1

    .line 38
    .line 39
    const-string p0, ""

    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_1
    if-gez v0, :cond_2

    .line 43
    .line 44
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    throw p0
.end method

.method public v(Ljava/util/List;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-ne v1, v2, :cond_2

    .line 11
    .line 12
    :cond_0
    invoke-virtual {p0}, Landroidx/collection/h;->s()Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 31
    .line 32
    if-eq v1, v2, :cond_0

    .line 33
    .line 34
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 35
    .line 36
    return-void

    .line 37
    :cond_2
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    throw p0
.end method

.method public v0(Landroidx/datastore/preferences/protobuf/z;Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-ne v1, v2, :cond_3

    .line 11
    .line 12
    :cond_0
    if-eqz p2, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0, v2}, Landroidx/collection/h;->J0(I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->B()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    goto :goto_0

    .line 22
    :cond_1
    invoke-virtual {p0, v2}, Landroidx/collection/h;->J0(I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->A()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    :goto_0
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_2

    .line 37
    .line 38
    return-void

    .line 39
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    iget v3, p0, Landroidx/collection/h;->e:I

    .line 44
    .line 45
    if-eq v1, v3, :cond_0

    .line 46
    .line 47
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 48
    .line 49
    return-void

    .line 50
    :cond_3
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    throw p0
.end method

.method public w()D
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    invoke-static {v0, v1}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    return-wide v0
.end method

.method public w0(Landroidx/glance/appwidget/protobuf/x;Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-ne v1, v2, :cond_3

    .line 11
    .line 12
    :cond_0
    if-eqz p2, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0, v2}, Landroidx/collection/h;->J0(I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->B()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    goto :goto_0

    .line 22
    :cond_1
    invoke-virtual {p0, v2}, Landroidx/collection/h;->J0(I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->A()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    :goto_0
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_2

    .line 37
    .line 38
    return-void

    .line 39
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    iget v3, p0, Landroidx/collection/h;->e:I

    .line 44
    .line 45
    if-eq v1, v3, :cond_0

    .line 46
    .line 47
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 48
    .line 49
    return-void

    .line 50
    :cond_3
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    throw p0
.end method

.method public x(Landroidx/datastore/preferences/protobuf/z;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eq v1, v2, :cond_2

    .line 11
    .line 12
    const/4 p0, 0x2

    .line 13
    if-ne v1, p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Landroidx/collection/h;->P0(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    add-int/2addr v1, p0

    .line 27
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->p()D

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-lt p0, v1, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c0;->b()Landroidx/datastore/preferences/protobuf/b0;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->p()D

    .line 51
    .line 52
    .line 53
    move-result-wide v1

    .line 54
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    :goto_0
    return-void

    .line 68
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 73
    .line 74
    if-eq v1, v2, :cond_2

    .line 75
    .line 76
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 77
    .line 78
    return-void
.end method

.method public x0(Ljava/util/List;Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    if-ne v1, v2, :cond_5

    .line 11
    .line 12
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/g0;

    .line 13
    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    if-nez p2, :cond_2

    .line 17
    .line 18
    move-object v1, p1

    .line 19
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/g0;

    .line 20
    .line 21
    :cond_0
    invoke-virtual {p0}, Landroidx/collection/h;->s()Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-interface {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/g0;->h0(Lcom/google/crypto/tink/shaded/protobuf/h;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    iget p2, p0, Landroidx/collection/h;->e:I

    .line 40
    .line 41
    if-eq p1, p2, :cond_0

    .line 42
    .line 43
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 44
    .line 45
    return-void

    .line 46
    :cond_2
    if-eqz p2, :cond_3

    .line 47
    .line 48
    invoke-virtual {p0}, Landroidx/collection/h;->y0()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    goto :goto_0

    .line 53
    :cond_3
    invoke-virtual {p0}, Landroidx/collection/h;->u0()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    :goto_0
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_4

    .line 65
    .line 66
    :goto_1
    return-void

    .line 67
    :cond_4
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 72
    .line 73
    if-eq v1, v2, :cond_2

    .line 74
    .line 75
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 76
    .line 77
    return-void

    .line 78
    :cond_5
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    throw p0
.end method

.method public y(Landroidx/glance/appwidget/protobuf/x;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/datastore/preferences/protobuf/k;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    and-int/lit8 v1, v1, 0x7

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eq v1, v2, :cond_2

    .line 11
    .line 12
    const/4 p0, 0x2

    .line 13
    if-ne v1, p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->D()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Landroidx/collection/h;->Q0(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    add-int/2addr v1, p0

    .line 27
    :cond_0
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->p()D

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->e()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-lt p0, v1, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-static {}, Landroidx/glance/appwidget/protobuf/a0;->b()Landroidx/glance/appwidget/protobuf/z;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->p()D

    .line 51
    .line 52
    .line 53
    move-result-wide v1

    .line 54
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->f()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    :goto_0
    return-void

    .line 68
    :cond_3
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/k;->C()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 73
    .line 74
    if-eq v1, v2, :cond_2

    .line 75
    .line 76
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 77
    .line 78
    return-void
.end method

.method public y0()Ljava/lang/String;
    .locals 4

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-lez v0, :cond_0

    .line 14
    .line 15
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->d:I

    .line 16
    .line 17
    iget v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    if-gt v0, v1, :cond_0

    .line 21
    .line 22
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->c:[B

    .line 23
    .line 24
    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/o1;->a:Lcom/google/crypto/tink/shaded/protobuf/q0;

    .line 25
    .line 26
    invoke-virtual {v3, v1, v2, v0}, Lcom/google/crypto/tink/shaded/protobuf/q0;->n([BII)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 31
    .line 32
    add-int/2addr v2, v0

    .line 33
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/j;->f:I

    .line 34
    .line 35
    return-object v1

    .line 36
    :cond_0
    if-nez v0, :cond_1

    .line 37
    .line 38
    const-string p0, ""

    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_1
    if-gtz v0, :cond_2

    .line 42
    .line 43
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    throw p0
.end method

.method public z(Ljava/util/List;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 4
    .line 5
    instance-of v1, p1, Lcom/google/crypto/tink/shaded/protobuf/n;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    const/4 v3, 0x1

    .line 9
    if-eqz v1, :cond_4

    .line 10
    .line 11
    move-object v1, p1

    .line 12
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/n;

    .line 13
    .line 14
    iget p1, p0, Landroidx/collection/h;->e:I

    .line 15
    .line 16
    and-int/lit8 p1, p1, 0x7

    .line 17
    .line 18
    if-eq p1, v3, :cond_2

    .line 19
    .line 20
    if-ne p1, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-static {p0}, Landroidx/collection/h;->R0(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    add-int/2addr p1, p0

    .line 34
    :cond_0
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    invoke-static {v2, v3}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 39
    .line 40
    .line 41
    move-result-wide v2

    .line 42
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/n;->e(D)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    if-lt p0, p1, :cond_0

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 58
    .line 59
    .line 60
    move-result-wide v2

    .line 61
    invoke-static {v2, v3}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 62
    .line 63
    .line 64
    move-result-wide v2

    .line 65
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/n;->e(D)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    if-eqz p1, :cond_3

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 80
    .line 81
    if-eq p1, v2, :cond_2

    .line 82
    .line 83
    iput p1, p0, Landroidx/collection/h;->g:I

    .line 84
    .line 85
    return-void

    .line 86
    :cond_4
    iget v1, p0, Landroidx/collection/h;->e:I

    .line 87
    .line 88
    and-int/lit8 v1, v1, 0x7

    .line 89
    .line 90
    if-eq v1, v3, :cond_7

    .line 91
    .line 92
    if-ne v1, v2, :cond_6

    .line 93
    .line 94
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    invoke-static {p0}, Landroidx/collection/h;->R0(I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    add-int/2addr v1, p0

    .line 106
    :cond_5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 107
    .line 108
    .line 109
    move-result-wide v2

    .line 110
    invoke-static {v2, v3}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 111
    .line 112
    .line 113
    move-result-wide v2

    .line 114
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->c()I

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    if-lt p0, v1, :cond_5

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    throw p0

    .line 133
    :cond_7
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->h()J

    .line 134
    .line 135
    .line 136
    move-result-wide v1

    .line 137
    invoke-static {v1, v2}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 138
    .line 139
    .line 140
    move-result-wide v1

    .line 141
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-eqz v1, :cond_8

    .line 153
    .line 154
    :goto_0
    return-void

    .line 155
    :cond_8
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    iget v2, p0, Landroidx/collection/h;->e:I

    .line 160
    .line 161
    if-eq v1, v2, :cond_7

    .line 162
    .line 163
    iput v1, p0, Landroidx/collection/h;->g:I

    .line 164
    .line 165
    return-void
.end method

.method public z0()I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/collection/h;->K0(I)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/j;->i()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method
