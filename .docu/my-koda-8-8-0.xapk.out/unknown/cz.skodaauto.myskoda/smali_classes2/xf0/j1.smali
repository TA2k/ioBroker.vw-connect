.class public final synthetic Lxf0/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Le3/n0;

.field public final synthetic g:J

.field public final synthetic h:F

.field public final synthetic i:Lt2/b;

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lay0/a;Le3/n0;JFLt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/j1;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/j1;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/j1;->f:Le3/n0;

    .line 9
    .line 10
    iput-wide p4, p0, Lxf0/j1;->g:J

    .line 11
    .line 12
    iput p6, p0, Lxf0/j1;->h:F

    .line 13
    .line 14
    iput-object p7, p0, Lxf0/j1;->i:Lt2/b;

    .line 15
    .line 16
    iput p8, p0, Lxf0/j1;->j:I

    .line 17
    .line 18
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
    iget p1, p0, Lxf0/j1;->j:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v8

    .line 17
    iget-object v0, p0, Lxf0/j1;->d:Lx2/s;

    .line 18
    .line 19
    iget-object v1, p0, Lxf0/j1;->e:Lay0/a;

    .line 20
    .line 21
    iget-object v2, p0, Lxf0/j1;->f:Le3/n0;

    .line 22
    .line 23
    iget-wide v3, p0, Lxf0/j1;->g:J

    .line 24
    .line 25
    iget v5, p0, Lxf0/j1;->h:F

    .line 26
    .line 27
    iget-object v6, p0, Lxf0/j1;->i:Lt2/b;

    .line 28
    .line 29
    invoke-static/range {v0 .. v8}, Lxf0/i0;->D(Lx2/s;Lay0/a;Le3/n0;JFLt2/b;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
