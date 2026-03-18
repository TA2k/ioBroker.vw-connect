.class public final synthetic Lh2/r3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/v3;

.field public final synthetic e:Ljava/lang/Long;

.field public final synthetic f:Ljava/lang/Long;

.field public final synthetic g:I

.field public final synthetic h:Lh2/g2;

.field public final synthetic i:Lx2/s;

.field public final synthetic j:J


# direct methods
.method public synthetic constructor <init>(Lh2/v3;Ljava/lang/Long;Ljava/lang/Long;ILh2/g2;Lx2/s;JI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/r3;->d:Lh2/v3;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/r3;->e:Ljava/lang/Long;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/r3;->f:Ljava/lang/Long;

    .line 9
    .line 10
    iput p4, p0, Lh2/r3;->g:I

    .line 11
    .line 12
    iput-object p5, p0, Lh2/r3;->h:Lh2/g2;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/r3;->i:Lx2/s;

    .line 15
    .line 16
    iput-wide p7, p0, Lh2/r3;->j:J

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v8, p1

    .line 2
    check-cast v8, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const p1, 0x186001

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result v9

    .line 16
    iget-object v0, p0, Lh2/r3;->d:Lh2/v3;

    .line 17
    .line 18
    iget-object v1, p0, Lh2/r3;->e:Ljava/lang/Long;

    .line 19
    .line 20
    iget-object v2, p0, Lh2/r3;->f:Ljava/lang/Long;

    .line 21
    .line 22
    iget v3, p0, Lh2/r3;->g:I

    .line 23
    .line 24
    iget-object v4, p0, Lh2/r3;->h:Lh2/g2;

    .line 25
    .line 26
    iget-object v5, p0, Lh2/r3;->i:Lx2/s;

    .line 27
    .line 28
    iget-wide v6, p0, Lh2/r3;->j:J

    .line 29
    .line 30
    invoke-virtual/range {v0 .. v9}, Lh2/v3;->b(Ljava/lang/Long;Ljava/lang/Long;ILh2/g2;Lx2/s;JLl2/o;I)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0
.end method
