.class public final Le5/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/util/HashMap;

.field public b:Ljava/util/HashMap;

.field public c:Ljava/util/HashMap;


# virtual methods
.method public a(Ld5/c;)F
    .locals 2

    .line 1
    iget-object v0, p0, Le5/f;->a:Ljava/util/HashMap;

    .line 2
    .line 3
    iget-object p0, p0, Le5/f;->b:Ljava/util/HashMap;

    .line 4
    .line 5
    instance-of v1, p1, Ld5/h;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    check-cast p1, Ld5/h;

    .line 10
    .line 11
    invoke-virtual {p1}, Ld5/c;->e()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Le5/d;

    .line 26
    .line 27
    invoke-interface {p0}, Le5/d;->value()F

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0

    .line 32
    :cond_0
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_2

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {p0}, Ljava/lang/Integer;->floatValue()F

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    return p0

    .line 49
    :cond_1
    instance-of p0, p1, Ld5/e;

    .line 50
    .line 51
    if-eqz p0, :cond_2

    .line 52
    .line 53
    check-cast p1, Ld5/e;

    .line 54
    .line 55
    invoke-virtual {p1}, Ld5/e;->i()F

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    return p0

    .line 60
    :cond_2
    const/4 p0, 0x0

    .line 61
    return p0
.end method
