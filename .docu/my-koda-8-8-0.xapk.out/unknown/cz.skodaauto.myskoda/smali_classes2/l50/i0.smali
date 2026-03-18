.class public final Ll50/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lj50/k;

.field public final b:Ll50/h0;


# direct methods
.method public constructor <init>(Lj50/k;Ll50/h0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/i0;->a:Lj50/k;

    .line 5
    .line 6
    iput-object p2, p0, Ll50/i0;->b:Ll50/h0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lmk0/a;)Ljava/lang/Boolean;
    .locals 4

    .line 1
    iget-object v0, p0, Ll50/i0;->b:Ll50/h0;

    .line 2
    .line 3
    iget-object p0, p0, Ll50/i0;->a:Lj50/k;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_2

    .line 7
    .line 8
    iget-object v2, p1, Lmk0/a;->b:Lmk0/d;

    .line 9
    .line 10
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const/4 v3, 0x1

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-eq v2, v3, :cond_0

    .line 18
    .line 19
    move-object v2, v1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    sget-object v2, Lm50/a;->f:Lm50/a;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    sget-object v2, Lm50/a;->e:Lm50/a;

    .line 25
    .line 26
    :goto_0
    if-eqz v2, :cond_2

    .line 27
    .line 28
    iget-object p0, p0, Lj50/k;->g:Lyy0/c2;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    new-instance p0, Lm50/b;

    .line 34
    .line 35
    invoke-direct {p0, v2, v3}, Lm50/b;-><init>(Lm50/a;Z)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, p0}, Ll50/h0;->a(Lm50/b;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    iget-object p0, p0, Lj50/k;->g:Lyy0/c2;

    .line 43
    .line 44
    invoke-virtual {p0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ll50/h0;->a(Lm50/b;)V

    .line 48
    .line 49
    .line 50
    const/4 v3, 0x0

    .line 51
    :goto_1
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lmk0/a;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll50/i0;->a(Lmk0/a;)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
