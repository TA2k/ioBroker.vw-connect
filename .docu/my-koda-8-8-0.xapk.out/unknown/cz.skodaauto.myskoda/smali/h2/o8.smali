.class public final synthetic Lh2/o8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Z


# direct methods
.method public synthetic constructor <init>(ZLay0/a;Lay0/a;Lay0/k;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lh2/o8;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lh2/o8;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/o8;->f:Lay0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/o8;->g:Lay0/k;

    .line 11
    .line 12
    iput-boolean p5, p0, Lh2/o8;->h:Z

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Lh2/s8;

    .line 3
    .line 4
    new-instance v0, Lh2/r8;

    .line 5
    .line 6
    iget-boolean v1, p0, Lh2/o8;->d:Z

    .line 7
    .line 8
    iget-object v2, p0, Lh2/o8;->e:Lay0/a;

    .line 9
    .line 10
    iget-object v3, p0, Lh2/o8;->f:Lay0/a;

    .line 11
    .line 12
    iget-object v5, p0, Lh2/o8;->g:Lay0/k;

    .line 13
    .line 14
    iget-boolean v6, p0, Lh2/o8;->h:Z

    .line 15
    .line 16
    invoke-direct/range {v0 .. v6}, Lh2/r8;-><init>(ZLay0/a;Lay0/a;Lh2/s8;Lay0/k;Z)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method
