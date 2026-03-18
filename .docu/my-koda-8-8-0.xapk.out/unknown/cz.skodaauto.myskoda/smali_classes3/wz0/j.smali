.class public final Lwz0/j;
.super Lb6/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Z


# direct methods
.method public constructor <init>(Lb11/a;Z)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lb6/f;-><init>(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iput-boolean p2, p0, Lwz0/j;->f:Z

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final p(B)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/j;->f:Z

    .line 2
    .line 3
    invoke-static {p1}, Llx0/s;->a(B)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lb6/f;->v(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {p0, p1}, Lb6/f;->t(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final r(I)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/j;->f:Z

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Integer;->toUnsignedString(I)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lb6/f;->v(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {p0, p1}, Lb6/f;->t(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final s(J)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/j;->f:Z

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljava/lang/Long;->toUnsignedString(J)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lb6/f;->v(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {p0, p1}, Lb6/f;->t(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final u(S)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lwz0/j;->f:Z

    .line 2
    .line 3
    invoke-static {p1}, Llx0/z;->a(S)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lb6/f;->v(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {p0, p1}, Lb6/f;->t(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
