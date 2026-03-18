.class public final synthetic Lh2/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/v;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Le3/n0;

.field public final synthetic i:J


# direct methods
.method public synthetic constructor <init>(Lh2/v;Lx2/s;FFLe3/n0;JI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/t;->d:Lh2/v;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/t;->e:Lx2/s;

    .line 7
    .line 8
    iput p3, p0, Lh2/t;->f:F

    .line 9
    .line 10
    iput p4, p0, Lh2/t;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Lh2/t;->h:Le3/n0;

    .line 13
    .line 14
    iput-wide p6, p0, Lh2/t;->i:J

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    move-object v7, p1

    .line 2
    check-cast v7, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const p1, 0x30001

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result v8

    .line 16
    iget-object v0, p0, Lh2/t;->d:Lh2/v;

    .line 17
    .line 18
    iget-object v1, p0, Lh2/t;->e:Lx2/s;

    .line 19
    .line 20
    iget v2, p0, Lh2/t;->f:F

    .line 21
    .line 22
    iget v3, p0, Lh2/t;->g:F

    .line 23
    .line 24
    iget-object v4, p0, Lh2/t;->h:Le3/n0;

    .line 25
    .line 26
    iget-wide v5, p0, Lh2/t;->i:J

    .line 27
    .line 28
    invoke-virtual/range {v0 .. v8}, Lh2/v;->a(Lx2/s;FFLe3/n0;JLl2/o;I)V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method
