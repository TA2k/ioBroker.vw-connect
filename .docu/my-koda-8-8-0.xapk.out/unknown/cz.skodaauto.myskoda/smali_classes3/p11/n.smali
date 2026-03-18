.class public final Lp11/n;
.super Lp11/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final P:Lp11/n;

.field public static final Q:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lp11/n;->Q:Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    new-instance v1, Lp11/n;

    .line 9
    .line 10
    sget-object v2, Lp11/m;->v1:Lp11/m;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v1, v2, v3}, Lp11/b;-><init>(Ljp/u1;Ln11/f;)V

    .line 14
    .line 15
    .line 16
    sput-object v1, Lp11/n;->P:Lp11/n;

    .line 17
    .line 18
    sget-object v2, Ln11/f;->e:Ln11/n;

    .line 19
    .line 20
    invoke-virtual {v0, v2, v1}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public static P()Lp11/n;
    .locals 1

    .line 1
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lp11/n;->Q(Ln11/f;)Lp11/n;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method public static Q(Ln11/f;)Lp11/n;
    .locals 4

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :cond_0
    sget-object v0, Lp11/n;->Q:Ljava/util/concurrent/ConcurrentHashMap;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lp11/n;

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    new-instance v1, Lp11/n;

    .line 18
    .line 19
    sget-object v2, Lp11/n;->P:Lp11/n;

    .line 20
    .line 21
    invoke-static {v2, p0}, Lp11/r;->R(Ljp/u1;Ln11/f;)Lp11/r;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-direct {v1, v2, v3}, Lp11/b;-><init>(Ljp/u1;Ln11/f;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lp11/n;

    .line 34
    .line 35
    if-eqz p0, :cond_1

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_1
    return-object v1
.end method


# virtual methods
.method public final I()Ljp/u1;
    .locals 0

    .line 1
    sget-object p0, Lp11/n;->P:Lp11/n;

    .line 2
    .line 3
    return-object p0
.end method

.method public final J(Ln11/f;)Ljp/u1;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    :cond_0
    invoke-virtual {p0}, Lp11/b;->m()Ln11/f;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-ne p1, v0, :cond_1

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_1
    invoke-static {p1}, Lp11/n;->Q(Ln11/f;)Lp11/n;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public final O(Lp11/a;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lp11/b;->d:Ljp/u1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljp/u1;->m()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Ln11/f;->e:Ln11/n;

    .line 8
    .line 9
    if-ne p0, v0, :cond_0

    .line 10
    .line 11
    new-instance p0, Lq11/d;

    .line 12
    .line 13
    sget-object v0, Lp11/o;->f:Lp11/o;

    .line 14
    .line 15
    sget-object v1, Ln11/b;->h:Ln11/b;

    .line 16
    .line 17
    invoke-direct {p0, v0}, Lq11/d;-><init>(Ln11/a;)V

    .line 18
    .line 19
    .line 20
    iput-object p0, p1, Lp11/a;->H:Ln11/a;

    .line 21
    .line 22
    iget-object v0, p0, Lq11/d;->g:Lq11/l;

    .line 23
    .line 24
    iput-object v0, p1, Lp11/a;->k:Ln11/g;

    .line 25
    .line 26
    new-instance v0, Lq11/k;

    .line 27
    .line 28
    sget-object v1, Ln11/b;->k:Ln11/b;

    .line 29
    .line 30
    iget-object v2, p0, Lq11/c;->e:Ln11/a;

    .line 31
    .line 32
    invoke-virtual {v2}, Ln11/a;->i()Ln11/g;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-direct {v0, p0, v2, v1}, Lq11/k;-><init>(Lq11/d;Ln11/g;Ln11/b;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p1, Lp11/a;->G:Ln11/a;

    .line 40
    .line 41
    new-instance p0, Lq11/k;

    .line 42
    .line 43
    iget-object v0, p1, Lp11/a;->H:Ln11/a;

    .line 44
    .line 45
    check-cast v0, Lq11/d;

    .line 46
    .line 47
    iget-object v1, p1, Lp11/a;->h:Ln11/g;

    .line 48
    .line 49
    sget-object v2, Ln11/b;->p:Ln11/b;

    .line 50
    .line 51
    invoke-direct {p0, v0, v1, v2}, Lq11/k;-><init>(Lq11/d;Ln11/g;Ln11/b;)V

    .line 52
    .line 53
    .line 54
    iput-object p0, p1, Lp11/a;->C:Ln11/a;

    .line 55
    .line 56
    :cond_0
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Lp11/n;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Lp11/n;

    .line 10
    .line 11
    invoke-virtual {p0}, Lp11/b;->m()Ln11/f;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p1}, Lp11/b;->m()Ln11/f;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p0, p1}, Ln11/f;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_1
    const/4 p0, 0x0

    .line 25
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lp11/b;->m()Ln11/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ln11/f;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    const v0, 0xc3857

    .line 10
    .line 11
    .line 12
    add-int/2addr p0, v0

    .line 13
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lp11/b;->m()Ln11/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "ISOChronology["

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Ln11/f;->d:Ljava/lang/String;

    .line 15
    .line 16
    const/16 v1, 0x5d

    .line 17
    .line 18
    invoke-static {v0, p0, v1}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_0
    const-string p0, "ISOChronology"

    .line 24
    .line 25
    return-object p0
.end method
