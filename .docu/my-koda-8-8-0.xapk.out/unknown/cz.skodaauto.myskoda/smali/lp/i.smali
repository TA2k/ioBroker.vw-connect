.class public final Llp/i;
.super Ljp/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Ljava/lang/Object;

.field public f:I

.field public final synthetic g:Llp/j;


# direct methods
.method public constructor <init>(Llp/j;I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    invoke-direct {p0, v1, v0}, Ljp/m;-><init>(IZ)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Llp/i;->g:Llp/j;

    .line 7
    .line 8
    sget-object v0, Llp/j;->m:Ljava/lang/Object;

    .line 9
    .line 10
    invoke-virtual {p1}, Llp/j;->b()[Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    aget-object p1, p1, p2

    .line 15
    .line 16
    iput-object p1, p0, Llp/i;->e:Ljava/lang/Object;

    .line 17
    .line 18
    iput p2, p0, Llp/i;->f:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    iget v0, p0, Llp/i;->f:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    iget-object v2, p0, Llp/i;->e:Ljava/lang/Object;

    .line 5
    .line 6
    iget-object v3, p0, Llp/i;->g:Llp/j;

    .line 7
    .line 8
    if-eq v0, v1, :cond_1

    .line 9
    .line 10
    invoke-virtual {v3}, Llp/j;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-ge v0, v1, :cond_1

    .line 15
    .line 16
    iget v0, p0, Llp/i;->f:I

    .line 17
    .line 18
    invoke-virtual {v3}, Llp/j;->b()[Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    aget-object v0, v1, v0

    .line 23
    .line 24
    invoke-static {v2, v0}, Llp/fg;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-void

    .line 32
    :cond_1
    :goto_0
    sget-object v0, Llp/j;->m:Ljava/lang/Object;

    .line 33
    .line 34
    invoke-virtual {v3, v2}, Llp/j;->h(Ljava/lang/Object;)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iput v0, p0, Llp/i;->f:I

    .line 39
    .line 40
    return-void
.end method

.method public final getKey()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Llp/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Llp/i;->g:Llp/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Llp/j;->d()Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Llp/i;->e:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-interface {v1, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    invoke-virtual {p0}, Llp/i;->a()V

    .line 17
    .line 18
    .line 19
    iget p0, p0, Llp/i;->f:I

    .line 20
    .line 21
    const/4 v1, -0x1

    .line 22
    if-ne p0, v1, :cond_1

    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    return-object p0

    .line 26
    :cond_1
    invoke-virtual {v0}, Llp/j;->c()[Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    aget-object p0, v0, p0

    .line 31
    .line 32
    return-object p0
.end method

.method public final setValue(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Llp/i;->g:Llp/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Llp/j;->d()Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-object v2, p0, Llp/i;->e:Ljava/lang/Object;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-interface {v1, v2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    invoke-virtual {p0}, Llp/i;->a()V

    .line 17
    .line 18
    .line 19
    iget v1, p0, Llp/i;->f:I

    .line 20
    .line 21
    const/4 v3, -0x1

    .line 22
    if-ne v1, v3, :cond_1

    .line 23
    .line 24
    invoke-virtual {v0, v2, p1}, Llp/j;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    const/4 p0, 0x0

    .line 28
    return-object p0

    .line 29
    :cond_1
    invoke-virtual {v0}, Llp/j;->c()[Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    aget-object v1, v2, v1

    .line 34
    .line 35
    iget p0, p0, Llp/i;->f:I

    .line 36
    .line 37
    invoke-virtual {v0}, Llp/j;->c()[Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    aput-object p1, v0, p0

    .line 42
    .line 43
    return-object v1
.end method
