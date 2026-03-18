.class public final La70/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:La70/e;


# direct methods
.method public constructor <init>(La70/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La70/c;->a:La70/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lb70/c;)V
    .locals 6

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p1, -0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    sget-object v0, La70/b;->a:[I

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    aget p1, v0, p1

    .line 12
    .line 13
    :goto_0
    const/4 v0, 0x1

    .line 14
    iget-object p0, p0, La70/c;->a:La70/e;

    .line 15
    .line 16
    if-eq p1, v0, :cond_2

    .line 17
    .line 18
    const/4 v0, 0x2

    .line 19
    if-eq p1, v0, :cond_1

    .line 20
    .line 21
    check-cast p0, Liy/b;

    .line 22
    .line 23
    invoke-virtual {p0}, Liy/b;->i()V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    check-cast p0, Liy/b;

    .line 28
    .line 29
    new-instance v0, Lul0/c;

    .line 30
    .line 31
    sget-object v1, Lly/b;->d2:Lly/b;

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    const/16 v5, 0x3e

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    const/4 v3, 0x0

    .line 38
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_2
    check-cast p0, Liy/b;

    .line 46
    .line 47
    new-instance v0, Lul0/c;

    .line 48
    .line 49
    sget-object v1, Lly/b;->c2:Lly/b;

    .line 50
    .line 51
    const/4 v4, 0x0

    .line 52
    const/16 v5, 0x3e

    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    const/4 v3, 0x0

    .line 56
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 60
    .line 61
    .line 62
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lb70/c;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, La70/c;->a(Lb70/c;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
