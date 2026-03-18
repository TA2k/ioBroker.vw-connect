.class public final Luc0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm0/l;


# virtual methods
.method public final a(Lcm0/b;Ld01/k0;)Ld01/k0;
    .locals 0

    .line 1
    const-string p0, "environment"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "request"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Lcm0/b;->g:Lcm0/b;

    .line 12
    .line 13
    if-ne p1, p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p2}, Ld01/k0;->b()Ld01/j0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const-string p1, "apiKey"

    .line 20
    .line 21
    const-string p2, "44a86edb-41fc-43e1-8bbe-42d3c18919c3"

    .line 22
    .line 23
    invoke-virtual {p0, p1, p2}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance p1, Ld01/k0;

    .line 27
    .line 28
    invoke-direct {p1, p0}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 29
    .line 30
    .line 31
    return-object p1

    .line 32
    :cond_0
    return-object p2
.end method
