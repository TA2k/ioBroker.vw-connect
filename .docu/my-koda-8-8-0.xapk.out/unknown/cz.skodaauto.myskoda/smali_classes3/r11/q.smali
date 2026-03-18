.class public final Lr11/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public d:Ln11/a;

.field public e:I

.field public f:Ljava/lang/String;

.field public g:Ljava/util/Locale;


# virtual methods
.method public final compareTo(Ljava/lang/Object;)I
    .locals 2

    .line 1
    check-cast p1, Lr11/q;

    .line 2
    .line 3
    iget-object p1, p1, Lr11/q;->d:Ln11/a;

    .line 4
    .line 5
    iget-object v0, p0, Lr11/q;->d:Ln11/a;

    .line 6
    .line 7
    invoke-virtual {v0}, Ln11/a;->p()Ln11/g;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p1}, Ln11/a;->p()Ln11/g;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-static {v0, v1}, Lr11/s;->a(Ln11/g;Ln11/g;)I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    return v0

    .line 22
    :cond_0
    iget-object p0, p0, Lr11/q;->d:Ln11/a;

    .line 23
    .line 24
    invoke-virtual {p0}, Ln11/a;->i()Ln11/g;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p1}, Ln11/a;->i()Ln11/g;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-static {p0, p1}, Lr11/s;->a(Ln11/g;Ln11/g;)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0
.end method
