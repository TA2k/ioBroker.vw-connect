.class public final Ll2/u1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ll2/a0;

.field public b:I

.field public c:Ll2/a;

.field public d:Lay0/n;

.field public e:I

.field public f:Landroidx/collection/h0;

.field public g:Landroidx/collection/q0;


# direct methods
.method public constructor <init>(Ll2/a0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/u1;->a:Ll2/a0;

    .line 5
    .line 6
    return-void
.end method

.method public static a(Ll2/h0;Landroidx/collection/q0;)Z
    .locals 2

    .line 1
    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.DerivedState<kotlin.Any?>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ll2/h0;->f:Ll2/n2;

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    sget-object v0, Ll2/x0;->i:Ll2/x0;

    .line 11
    .line 12
    :cond_0
    invoke-virtual {p0}, Ll2/h0;->o()Ll2/g0;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    iget-object v1, v1, Ll2/g0;->f:Ljava/lang/Object;

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-interface {v0, v1, p0}, Ll2/n2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    xor-int/lit8 p0, p0, 0x1

    .line 27
    .line 28
    return p0
.end method


# virtual methods
.method public final b()Z
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/u1;->a:Ll2/a0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_1

    .line 5
    .line 6
    iget-object p0, p0, Ll2/u1;->c:Ll2/a;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0}, Ll2/a;->a()Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move p0, v1

    .line 16
    :goto_0
    if-eqz p0, :cond_1

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_1
    return v1
.end method

.method public final c()V
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/u1;->a:Ll2/a0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {v0, p0, v1}, Ll2/a0;->r(Ll2/u1;Ljava/lang/Object;)Ll2/s0;

    .line 7
    .line 8
    .line 9
    :cond_0
    return-void
.end method

.method public final d(Ljava/lang/Object;)Ll2/s0;
    .locals 1

    .line 1
    iget-object v0, p0, Ll2/u1;->a:Ll2/a0;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {v0, p0, p1}, Ll2/a0;->r(Ll2/u1;Ljava/lang/Object;)Ll2/s0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object p0

    .line 13
    :cond_1
    :goto_0
    sget-object p0, Ll2/s0;->d:Ll2/s0;

    .line 14
    .line 15
    return-object p0
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/u1;->a:Ll2/a0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    iput-boolean v1, v0, Ll2/a0;->r:Z

    .line 7
    .line 8
    iget-object v0, v0, Ll2/a0;->w:Lh6/e;

    .line 9
    .line 10
    invoke-virtual {v0}, Lh6/e;->w()V

    .line 11
    .line 12
    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    iput-object v0, p0, Ll2/u1;->a:Ll2/a0;

    .line 15
    .line 16
    iput-object v0, p0, Ll2/u1;->f:Landroidx/collection/h0;

    .line 17
    .line 18
    iput-object v0, p0, Ll2/u1;->g:Landroidx/collection/q0;

    .line 19
    .line 20
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 21
    .line 22
    return-void
.end method

.method public final f(Z)V
    .locals 1

    .line 1
    iget v0, p0, Ll2/u1;->b:I

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    or-int/lit8 p1, v0, 0x20

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    and-int/lit8 p1, v0, -0x21

    .line 9
    .line 10
    :goto_0
    iput p1, p0, Ll2/u1;->b:I

    .line 11
    .line 12
    return-void
.end method
