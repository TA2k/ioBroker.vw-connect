.class public final synthetic Lj2/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lj2/h;

.field public final synthetic e:Lj2/p;

.field public final synthetic f:Z

.field public final synthetic g:Lx2/s;

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:F

.field public final synthetic k:I

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Lj2/h;Lj2/p;ZLx2/s;JJFII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj2/a;->d:Lj2/h;

    .line 5
    .line 6
    iput-object p2, p0, Lj2/a;->e:Lj2/p;

    .line 7
    .line 8
    iput-boolean p3, p0, Lj2/a;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lj2/a;->g:Lx2/s;

    .line 11
    .line 12
    iput-wide p5, p0, Lj2/a;->h:J

    .line 13
    .line 14
    iput-wide p7, p0, Lj2/a;->i:J

    .line 15
    .line 16
    iput p9, p0, Lj2/a;->j:F

    .line 17
    .line 18
    iput p10, p0, Lj2/a;->k:I

    .line 19
    .line 20
    iput p11, p0, Lj2/a;->l:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v9, p1

    .line 2
    check-cast v9, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lj2/a;->k:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v10

    .line 17
    iget-object v0, p0, Lj2/a;->d:Lj2/h;

    .line 18
    .line 19
    iget-object v1, p0, Lj2/a;->e:Lj2/p;

    .line 20
    .line 21
    iget-boolean v2, p0, Lj2/a;->f:Z

    .line 22
    .line 23
    iget-object v3, p0, Lj2/a;->g:Lx2/s;

    .line 24
    .line 25
    iget-wide v4, p0, Lj2/a;->h:J

    .line 26
    .line 27
    iget-wide v6, p0, Lj2/a;->i:J

    .line 28
    .line 29
    iget v8, p0, Lj2/a;->j:F

    .line 30
    .line 31
    iget v11, p0, Lj2/a;->l:I

    .line 32
    .line 33
    invoke-virtual/range {v0 .. v11}, Lj2/h;->a(Lj2/p;ZLx2/s;JJFLl2/o;II)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
