.class public abstract Lkp/fa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Landroid/text/style/LeadingMarginSpan;Lgy0/j;Ltm/f;)Ltm/e;
    .locals 6

    .line 1
    new-instance v0, Ltm/e;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-interface {p0, v1}, Landroid/text/style/LeadingMarginSpan;->getLeadingMargin(Z)I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-interface {p0, v2}, Landroid/text/style/LeadingMarginSpan;->getLeadingMargin(Z)I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    iget v3, p1, Lgy0/h;->d:I

    .line 14
    .line 15
    iget v4, p1, Lgy0/h;->e:I

    .line 16
    .line 17
    move-object v5, p2

    .line 18
    invoke-direct/range {v0 .. v5}, Ltm/e;-><init>(IIIILtm/f;)V

    .line 19
    .line 20
    .line 21
    return-object v0
.end method

.method public static final b()Lh21/b;
    .locals 3

    .line 1
    sget-object v0, Llc0/l;->e:Llc0/l;

    .line 2
    .line 3
    new-instance v0, Lh21/b;

    .line 4
    .line 5
    const-string v1, "Connect"

    .line 6
    .line 7
    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 8
    .line 9
    invoke-virtual {v1, v2}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-string v2, "toLowerCase(...)"

    .line 14
    .line 15
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {v0, v1}, Lh21/b;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v0
.end method

.method public static final c(Ljava/lang/String;)Lh21/b;
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh21/b;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Lh21/b;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
