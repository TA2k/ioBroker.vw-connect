.class public final synthetic Le71/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Z

.field public final synthetic f:Le71/g;

.field public final synthetic g:Lh71/x;

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/Float;

.field public final synthetic j:F

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;ZLe71/g;Lh71/x;ZLjava/lang/Float;FLay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le71/n;->d:Lx2/s;

    .line 5
    .line 6
    iput-boolean p2, p0, Le71/n;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Le71/n;->f:Le71/g;

    .line 9
    .line 10
    iput-object p4, p0, Le71/n;->g:Lh71/x;

    .line 11
    .line 12
    iput-boolean p5, p0, Le71/n;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Le71/n;->i:Ljava/lang/Float;

    .line 15
    .line 16
    iput p7, p0, Le71/n;->j:F

    .line 17
    .line 18
    iput-object p8, p0, Le71/n;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, Le71/n;->l:Lay0/a;

    .line 21
    .line 22
    iput-object p10, p0, Le71/n;->m:Lay0/a;

    .line 23
    .line 24
    iput p11, p0, Le71/n;->n:I

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Le71/n;->n:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v11

    .line 17
    iget-object v0, p0, Le71/n;->d:Lx2/s;

    .line 18
    .line 19
    iget-boolean v1, p0, Le71/n;->e:Z

    .line 20
    .line 21
    iget-object v2, p0, Le71/n;->f:Le71/g;

    .line 22
    .line 23
    iget-object v3, p0, Le71/n;->g:Lh71/x;

    .line 24
    .line 25
    iget-boolean v4, p0, Le71/n;->h:Z

    .line 26
    .line 27
    iget-object v5, p0, Le71/n;->i:Ljava/lang/Float;

    .line 28
    .line 29
    iget v6, p0, Le71/n;->j:F

    .line 30
    .line 31
    iget-object v7, p0, Le71/n;->k:Lay0/a;

    .line 32
    .line 33
    iget-object v8, p0, Le71/n;->l:Lay0/a;

    .line 34
    .line 35
    iget-object v9, p0, Le71/n;->m:Lay0/a;

    .line 36
    .line 37
    invoke-static/range {v0 .. v11}, Lkp/j0;->a(Lx2/s;ZLe71/g;Lh71/x;ZLjava/lang/Float;FLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0
.end method
