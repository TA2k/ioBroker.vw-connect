.class public final Lwx0/e;
.super Lwx0/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public b:Z

.field public c:[Ljava/io/File;

.field public d:I


# virtual methods
.method public final a()Ljava/io/File;
    .locals 5

    .line 1
    iget-boolean v0, p0, Lwx0/e;->b:Z

    .line 2
    .line 3
    iget-object v1, p0, Lwx0/g;->a:Ljava/io/File;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p0, Lwx0/e;->b:Z

    .line 9
    .line 10
    return-object v1

    .line 11
    :cond_0
    iget-object v0, p0, Lwx0/e;->c:[Ljava/io/File;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    iget v3, p0, Lwx0/e;->d:I

    .line 17
    .line 18
    array-length v4, v0

    .line 19
    if-ge v3, v4, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    return-object v2

    .line 23
    :cond_2
    :goto_0
    if-nez v0, :cond_4

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/io/File;->listFiles()[Ljava/io/File;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iput-object v0, p0, Lwx0/e;->c:[Ljava/io/File;

    .line 30
    .line 31
    if-eqz v0, :cond_3

    .line 32
    .line 33
    array-length v0, v0

    .line 34
    if-nez v0, :cond_4

    .line 35
    .line 36
    :cond_3
    return-object v2

    .line 37
    :cond_4
    iget-object v0, p0, Lwx0/e;->c:[Ljava/io/File;

    .line 38
    .line 39
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget v1, p0, Lwx0/e;->d:I

    .line 43
    .line 44
    add-int/lit8 v2, v1, 0x1

    .line 45
    .line 46
    iput v2, p0, Lwx0/e;->d:I

    .line 47
    .line 48
    aget-object p0, v0, v1

    .line 49
    .line 50
    return-object p0
.end method
