.class public final synthetic Lh2/z8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/a9;

.field public final synthetic e:Lh2/u7;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Z

.field public final synthetic h:Lh2/u8;

.field public final synthetic i:Lay0/n;

.field public final synthetic j:Lay0/o;

.field public final synthetic k:F

.field public final synthetic l:F

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Lh2/a9;Lh2/u7;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/z8;->d:Lh2/a9;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/z8;->e:Lh2/u7;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/z8;->f:Lx2/s;

    .line 9
    .line 10
    iput-boolean p4, p0, Lh2/z8;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Lh2/z8;->h:Lh2/u8;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/z8;->i:Lay0/n;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/z8;->j:Lay0/o;

    .line 17
    .line 18
    iput p8, p0, Lh2/z8;->k:F

    .line 19
    .line 20
    iput p9, p0, Lh2/z8;->l:F

    .line 21
    .line 22
    iput p10, p0, Lh2/z8;->m:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

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
    iget p1, p0, Lh2/z8;->m:I

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
    iget-object v0, p0, Lh2/z8;->d:Lh2/a9;

    .line 18
    .line 19
    iget-object v1, p0, Lh2/z8;->e:Lh2/u7;

    .line 20
    .line 21
    iget-object v2, p0, Lh2/z8;->f:Lx2/s;

    .line 22
    .line 23
    iget-boolean v3, p0, Lh2/z8;->g:Z

    .line 24
    .line 25
    iget-object v4, p0, Lh2/z8;->h:Lh2/u8;

    .line 26
    .line 27
    iget-object v5, p0, Lh2/z8;->i:Lay0/n;

    .line 28
    .line 29
    iget-object v6, p0, Lh2/z8;->j:Lay0/o;

    .line 30
    .line 31
    iget v7, p0, Lh2/z8;->k:F

    .line 32
    .line 33
    iget v8, p0, Lh2/z8;->l:F

    .line 34
    .line 35
    invoke-virtual/range {v0 .. v10}, Lh2/a9;->d(Lh2/u7;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;I)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0
.end method
