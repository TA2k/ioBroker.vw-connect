.class public final Le1/n1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/q2;


# static fields
.field public static final i:Lu2/l;


# instance fields
.field public final a:Ll2/g1;

.field public final b:Ll2/g1;

.field public final c:Li1/l;

.field public final d:Ll2/g1;

.field public e:F

.field public final f:Lg1/f0;

.field public final g:Ll2/h0;

.field public final h:Ll2/h0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ldl0/k;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Ldl0/k;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Ldj/a;

    .line 8
    .line 9
    const/16 v2, 0x12

    .line 10
    .line 11
    invoke-direct {v1, v2}, Ldj/a;-><init>(I)V

    .line 12
    .line 13
    .line 14
    new-instance v2, Lu2/l;

    .line 15
    .line 16
    invoke-direct {v2, v0, v1}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 17
    .line 18
    .line 19
    sput-object v2, Le1/n1;->i:Lu2/l;

    .line 20
    .line 21
    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ll2/g1;

    .line 5
    .line 6
    invoke-direct {v0, p1}, Ll2/g1;-><init>(I)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Le1/n1;->a:Ll2/g1;

    .line 10
    .line 11
    new-instance p1, Ll2/g1;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    invoke-direct {p1, v0}, Ll2/g1;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Le1/n1;->b:Ll2/g1;

    .line 18
    .line 19
    new-instance p1, Li1/l;

    .line 20
    .line 21
    invoke-direct {p1}, Li1/l;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Le1/n1;->c:Li1/l;

    .line 25
    .line 26
    new-instance p1, Ll2/g1;

    .line 27
    .line 28
    const v0, 0x7fffffff

    .line 29
    .line 30
    .line 31
    invoke-direct {p1, v0}, Ll2/g1;-><init>(I)V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Le1/n1;->d:Ll2/g1;

    .line 35
    .line 36
    new-instance p1, Le1/l1;

    .line 37
    .line 38
    const/4 v0, 0x0

    .line 39
    invoke-direct {p1, p0, v0}, Le1/l1;-><init>(Le1/n1;I)V

    .line 40
    .line 41
    .line 42
    new-instance v0, Lg1/f0;

    .line 43
    .line 44
    invoke-direct {v0, p1}, Lg1/f0;-><init>(Lay0/k;)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Le1/n1;->f:Lg1/f0;

    .line 48
    .line 49
    new-instance p1, Le1/m1;

    .line 50
    .line 51
    const/4 v0, 0x0

    .line 52
    invoke-direct {p1, p0, v0}, Le1/m1;-><init>(Le1/n1;I)V

    .line 53
    .line 54
    .line 55
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iput-object p1, p0, Le1/n1;->g:Ll2/h0;

    .line 60
    .line 61
    new-instance p1, Le1/m1;

    .line 62
    .line 63
    const/4 v0, 0x1

    .line 64
    invoke-direct {p1, p0, v0}, Le1/m1;-><init>(Le1/n1;I)V

    .line 65
    .line 66
    .line 67
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput-object p1, p0, Le1/n1;->h:Ll2/h0;

    .line 72
    .line 73
    return-void
.end method

.method public static f(Le1/n1;ILkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lc1/f1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x7

    .line 5
    invoke-direct {v0, v1, v2}, Lc1/f1;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Le1/n1;->a:Ll2/g1;

    .line 9
    .line 10
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    sub-int/2addr p1, v1

    .line 15
    int-to-float p1, p1

    .line 16
    invoke-static {p0, p1, v0, p2}, Lg1/h3;->a(Lg1/q2;FLc1/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    if-ne p0, p1, :cond_0

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Le1/n1;->f:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lg1/f0;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Le1/n1;->h:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Le1/n1;->f:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Lg1/f0;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Le1/n1;->g:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Le1/n1;->f:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lg1/f0;->e(F)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
