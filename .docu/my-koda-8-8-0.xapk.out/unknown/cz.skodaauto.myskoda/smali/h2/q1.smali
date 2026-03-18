.class public final synthetic Lh2/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Lh2/y1;

.field public final synthetic e:Li2/z;

.field public final synthetic f:Li2/e0;

.field public final synthetic g:Ljava/util/Locale;

.field public final synthetic h:I

.field public final synthetic i:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lh2/y1;Li2/z;Li2/e0;Ljava/util/Locale;ILl2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/q1;->d:Lh2/y1;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/q1;->e:Li2/z;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/q1;->f:Li2/e0;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/q1;->g:Ljava/util/Locale;

    .line 11
    .line 12
    iput p5, p0, Lh2/q1;->h:I

    .line 13
    .line 14
    iput-object p6, p0, Lh2/q1;->i:Ll2/b1;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lh2/q1;->i:Ll2/b1;

    .line 2
    .line 3
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ll4/v;

    .line 8
    .line 9
    iget-object v1, v1, Ll4/v;->a:Lg4/g;

    .line 10
    .line 11
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-lez v1, :cond_0

    .line 18
    .line 19
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Ll4/v;

    .line 24
    .line 25
    iget-object v0, v0, Ll4/v;->a:Lg4/g;

    .line 26
    .line 27
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v1, p0, Lh2/q1;->f:Li2/e0;

    .line 30
    .line 31
    iget-object v1, v1, Li2/e0;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v2, p0, Lh2/q1;->e:Li2/z;

    .line 34
    .line 35
    iget-object v3, p0, Lh2/q1;->g:Ljava/util/Locale;

    .line 36
    .line 37
    invoke-virtual {v2, v0, v1, v3}, Li2/z;->d(Ljava/lang/String;Ljava/lang/String;Ljava/util/Locale;)Li2/y;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iget-object v1, p0, Lh2/q1;->d:Lh2/y1;

    .line 42
    .line 43
    iget p0, p0, Lh2/q1;->h:I

    .line 44
    .line 45
    invoke-virtual {v1, v0, p0, v3}, Lh2/y1;->a(Li2/y;ILjava/util/Locale;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    const-string p0, ""

    .line 51
    .line 52
    :goto_0
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
