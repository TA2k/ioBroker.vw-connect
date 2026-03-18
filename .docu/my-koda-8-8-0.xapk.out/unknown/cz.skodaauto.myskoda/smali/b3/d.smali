.class public final Lb3/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt4/c;


# instance fields
.field public d:Lb3/b;

.field public e:Lb3/g;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lb3/i;->d:Lb3/i;

    .line 5
    .line 6
    iput-object v0, p0, Lb3/d;->d:Lb3/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Lb3/d;->d:Lb3/b;

    .line 2
    .line 3
    invoke-interface {p0}, Lb3/b;->a()Lt4/c;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Lt4/c;->a()F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final b(Lay0/k;)Lb3/g;
    .locals 1

    .line 1
    new-instance v0, Lb3/g;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, v0, Lb3/g;->d:Lay0/k;

    .line 7
    .line 8
    iput-object v0, p0, Lb3/d;->e:Lb3/g;

    .line 9
    .line 10
    return-object v0
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget-object p0, p0, Lb3/d;->d:Lb3/b;

    .line 2
    .line 3
    invoke-interface {p0}, Lb3/b;->a()Lt4/c;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method
