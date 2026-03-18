.class public final Lkw/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw/b;


# instance fields
.field public d:Lkw/g;

.field public e:F

.field public f:Ld3/a;


# virtual methods
.method public final q(Lmw/j;Lnw/g;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkw/c;->d:Lkw/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_2

    .line 5
    .line 6
    iget v2, p0, Lkw/c;->e:F

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget-object p0, p0, Lkw/c;->f:Ld3/a;

    .line 12
    .line 13
    if-eqz p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p2, v0, v2, p1, p0}, Lnw/g;->b(Lkw/g;FLjava/lang/Object;Ld3/a;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_1
    const-string p0, "insets"

    .line 20
    .line 21
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw v1

    .line 25
    :cond_2
    const-string p0, "context"

    .line 26
    .line 27
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw v1
.end method
