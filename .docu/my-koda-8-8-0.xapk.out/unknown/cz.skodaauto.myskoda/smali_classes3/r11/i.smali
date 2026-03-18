.class public Lr11/i;
.super Lr11/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:I


# direct methods
.method public constructor <init>(Ln11/b;IZI)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lr11/h;-><init>(Ln11/b;IZ)V

    .line 2
    .line 3
    .line 4
    iput p4, p0, Lr11/i;->g:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 0

    .line 1
    iget p5, p0, Lr11/i;->g:I

    .line 2
    .line 3
    :try_start_0
    iget-object p0, p0, Lr11/h;->d:Ln11/b;

    .line 4
    .line 5
    invoke-virtual {p0, p4}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0, p2, p3}, Ln11/a;->b(J)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p1, p0, p5}, Lr11/u;->a(Ljava/lang/Appendable;II)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :catch_0
    invoke-static {p5, p1}, Lvp/y1;->M(ILjava/lang/StringBuilder;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 1

    .line 1
    iget-object p3, p0, Lr11/h;->d:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {p2, p3}, Lo11/b;->g(Ln11/b;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget p0, p0, Lr11/i;->g:I

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    :try_start_0
    invoke-virtual {p2, p3}, Lo11/b;->b(Ln11/b;)I

    .line 12
    .line 13
    .line 14
    move-result p2

    .line 15
    invoke-static {p1, p2, p0}, Lr11/u;->a(Ljava/lang/Appendable;II)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :catch_0
    invoke-static {p0, p1}, Lvp/y1;->M(ILjava/lang/StringBuilder;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    invoke-static {p0, p1}, Lvp/y1;->M(ILjava/lang/StringBuilder;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final e()I
    .locals 0

    .line 1
    iget p0, p0, Lr11/h;->e:I

    .line 2
    .line 3
    return p0
.end method
