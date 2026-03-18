.class public final Lwc/g;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lxh/e;

.field public final e:Lth/b;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;

.field public final h:Llx0/q;


# direct methods
.method public constructor <init>(Lxh/e;Lth/b;ZLjava/lang/String;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwc/g;->d:Lxh/e;

    .line 5
    .line 6
    iput-object p2, p0, Lwc/g;->e:Lth/b;

    .line 7
    .line 8
    new-instance v0, Lwc/f;

    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    const/4 p2, 0x0

    .line 12
    if-nez p3, :cond_0

    .line 13
    .line 14
    if-eqz p4, :cond_0

    .line 15
    .line 16
    move v5, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v5, p2

    .line 19
    :goto_0
    if-nez p4, :cond_2

    .line 20
    .line 21
    if-eqz p3, :cond_2

    .line 22
    .line 23
    :cond_1
    move v6, p2

    .line 24
    goto :goto_1

    .line 25
    :cond_2
    if-eqz p4, :cond_3

    .line 26
    .line 27
    if-eqz p3, :cond_1

    .line 28
    .line 29
    :cond_3
    move v6, p1

    .line 30
    :goto_1
    const-string v1, ""

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v4, 0x0

    .line 35
    invoke-direct/range {v0 .. v6}, Lwc/f;-><init>(Ljava/lang/String;ZZZZZ)V

    .line 36
    .line 37
    .line 38
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iput-object p1, p0, Lwc/g;->f:Lyy0/c2;

    .line 43
    .line 44
    new-instance p2, Lyy0/l1;

    .line 45
    .line 46
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 47
    .line 48
    .line 49
    iput-object p2, p0, Lwc/g;->g:Lyy0/l1;

    .line 50
    .line 51
    new-instance p1, Lvd/i;

    .line 52
    .line 53
    const/16 p2, 0x19

    .line 54
    .line 55
    invoke-direct {p1, p2}, Lvd/i;-><init>(I)V

    .line 56
    .line 57
    .line 58
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    iput-object p1, p0, Lwc/g;->h:Llx0/q;

    .line 63
    .line 64
    return-void
.end method
