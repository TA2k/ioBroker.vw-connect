.class public final Lkf0/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# direct methods
.method public static a(Lss0/k;)Llf0/h;
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lss0/k;->d:Lss0/m;

    .line 7
    .line 8
    sget-object v1, Lss0/m;->i:Lss0/m;

    .line 9
    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    sget-object p0, Llf0/h;->h:Llf0/h;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    sget-object v1, Lss0/m;->j:Lss0/m;

    .line 16
    .line 17
    if-ne v0, v1, :cond_1

    .line 18
    .line 19
    sget-object p0, Llf0/h;->i:Llf0/h;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    sget-object v1, Lss0/m;->k:Lss0/m;

    .line 23
    .line 24
    if-ne v0, v1, :cond_2

    .line 25
    .line 26
    sget-object p0, Llf0/h;->j:Llf0/h;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_2
    sget-object v1, Lss0/m;->e:Lss0/m;

    .line 30
    .line 31
    if-ne v0, v1, :cond_3

    .line 32
    .line 33
    sget-object p0, Llf0/h;->d:Llf0/h;

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    sget-object v1, Lss0/m;->f:Lss0/m;

    .line 37
    .line 38
    if-ne v0, v1, :cond_4

    .line 39
    .line 40
    sget-object p0, Llf0/h;->e:Llf0/h;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_4
    invoke-static {p0}, Lkp/p8;->b(Lss0/k;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_5

    .line 48
    .line 49
    sget-object p0, Llf0/h;->f:Llf0/h;

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_5
    iget-boolean p0, p0, Lss0/k;->l:Z

    .line 53
    .line 54
    if-eqz p0, :cond_6

    .line 55
    .line 56
    sget-object p0, Llf0/h;->g:Llf0/h;

    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_6
    sget-object p0, Llf0/h;->k:Llf0/h;

    .line 60
    .line 61
    return-object p0
.end method


# virtual methods
.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast p0, Lss0/k;

    .line 4
    .line 5
    invoke-static {p0}, Lkf0/f0;->a(Lss0/k;)Llf0/h;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
