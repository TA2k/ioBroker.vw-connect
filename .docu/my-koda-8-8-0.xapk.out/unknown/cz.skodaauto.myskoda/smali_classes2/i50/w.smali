.class public final Li50/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lh50/i0;

.field public final synthetic g:Lay0/a;


# direct methods
.method public constructor <init>(ZLay0/a;Lh50/i0;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Li50/w;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Li50/w;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Li50/w;->f:Lh50/i0;

    .line 9
    .line 10
    iput-object p4, p0, Li50/w;->g:Lay0/a;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-boolean v0, p0, Li50/w;->d:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Li50/w;->e:Lay0/a;

    .line 6
    .line 7
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    iget-object v0, p0, Li50/w;->f:Lh50/i0;

    .line 12
    .line 13
    instance-of v0, v0, Lh50/h0;

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    iget-object p0, p0, Li50/w;->g:Lay0/a;

    .line 18
    .line 19
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    :cond_1
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method
