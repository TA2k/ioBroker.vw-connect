.class public final Lw70/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# direct methods
.method public static a(Ljava/lang/String;)Lx70/b;
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "FR"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    new-instance p0, Lx70/b;

    .line 15
    .line 16
    const v0, 0x7f1211b3

    .line 17
    .line 18
    .line 19
    const v1, 0x7f1211b2

    .line 20
    .line 21
    .line 22
    invoke-direct {p0, v0, v1}, Lx70/b;-><init>(II)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_0
    const-string v0, "IT"

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_1

    .line 33
    .line 34
    new-instance p0, Lx70/b;

    .line 35
    .line 36
    const v0, 0x7f1211b6

    .line 37
    .line 38
    .line 39
    const v1, 0x7f1211b5

    .line 40
    .line 41
    .line 42
    invoke-direct {p0, v0, v1}, Lx70/b;-><init>(II)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_1
    const/4 p0, 0x0

    .line 47
    return-object p0
.end method


# virtual methods
.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast p0, Ljava/lang/String;

    .line 4
    .line 5
    invoke-static {p0}, Lw70/n;->a(Ljava/lang/String;)Lx70/b;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
