.class public abstract Lq11/c;
.super Lq11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Ln11/a;


# direct methods
.method public constructor <init>(Ln11/a;Ln11/b;)V
    .locals 0

    .line 1
    invoke-direct {p0, p2}, Lq11/a;-><init>(Ln11/b;)V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    invoke-virtual {p1}, Ln11/a;->s()Z

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    if-eqz p2, :cond_0

    .line 11
    .line 12
    iput-object p1, p0, Lq11/c;->e:Ln11/a;

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 16
    .line 17
    const-string p1, "The field must be supported"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    const-string p1, "The field must not be null"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method


# virtual methods
.method public i()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/a;->i()Ln11/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public p()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/a;->p()Ln11/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
