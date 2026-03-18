.class public final synthetic Lh2/ta;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lay0/n;

.field public final synthetic h:J

.field public final synthetic i:J


# direct methods
.method public synthetic constructor <init>(ZLay0/a;Lx2/s;Lay0/n;JJI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lh2/ta;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lh2/ta;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/ta;->f:Lx2/s;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/ta;->g:Lay0/n;

    .line 11
    .line 12
    iput-wide p5, p0, Lh2/ta;->h:J

    .line 13
    .line 14
    iput-wide p7, p0, Lh2/ta;->i:J

    .line 15
    .line 16
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
    const/16 p1, 0x6c01

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v9

    .line 15
    iget-boolean v0, p0, Lh2/ta;->d:Z

    .line 16
    .line 17
    iget-object v1, p0, Lh2/ta;->e:Lay0/a;

    .line 18
    .line 19
    iget-object v2, p0, Lh2/ta;->f:Lx2/s;

    .line 20
    .line 21
    iget-object v3, p0, Lh2/ta;->g:Lay0/n;

    .line 22
    .line 23
    iget-wide v4, p0, Lh2/ta;->h:J

    .line 24
    .line 25
    iget-wide v6, p0, Lh2/ta;->i:J

    .line 26
    .line 27
    invoke-static/range {v0 .. v9}, Lh2/wa;->b(ZLay0/a;Lx2/s;Lay0/n;JJLl2/o;I)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0
.end method
