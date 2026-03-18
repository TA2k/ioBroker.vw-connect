.class public final Ly01/g;
.super Ly01/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Z

.field public final c:Lw01/b;


# direct methods
.method public constructor <init>(II)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    new-instance v0, Lw01/b;

    .line 13
    .line 14
    invoke-direct {v0, p1, p2}, Lw01/b;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Ly01/g;->c:Lw01/b;

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    iput-boolean p1, p0, Ly01/g;->b:Z

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final b(ILjava/io/StringWriter;)Z
    .locals 6

    .line 1
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Ly01/g;->c:Lw01/b;

    .line 6
    .line 7
    iget-object v2, v1, Lw01/b;->d:Lw01/a;

    .line 8
    .line 9
    iget-object v3, v1, Lw01/b;->g:Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    invoke-interface {v0, v3}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, -0x1

    .line 19
    const/4 v4, 0x1

    .line 20
    const/4 v5, 0x0

    .line 21
    if-le v2, v3, :cond_0

    .line 22
    .line 23
    iget-object v1, v1, Lw01/b;->f:Ljava/lang/Integer;

    .line 24
    .line 25
    invoke-interface {v0, v1}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-ge v0, v4, :cond_0

    .line 30
    .line 31
    move v0, v4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move v0, v5

    .line 34
    :goto_0
    iget-boolean p0, p0, Ly01/g;->b:Z

    .line 35
    .line 36
    if-eq p0, v0, :cond_1

    .line 37
    .line 38
    return v5

    .line 39
    :cond_1
    const-string p0, "&#"

    .line 40
    .line 41
    invoke-virtual {p2, p0}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const/16 p0, 0xa

    .line 45
    .line 46
    invoke-static {p1, p0}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-virtual {p2, p0}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    const/16 p0, 0x3b

    .line 54
    .line 55
    invoke-virtual {p2, p0}, Ljava/io/Writer;->write(I)V

    .line 56
    .line 57
    .line 58
    return v4
.end method
