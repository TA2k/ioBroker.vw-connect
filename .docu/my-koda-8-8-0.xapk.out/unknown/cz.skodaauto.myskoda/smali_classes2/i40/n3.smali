.class public final synthetic Li40/n3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:F

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:Lg4/p0;

.field public final synthetic j:Landroid/net/Uri;

.field public final synthetic k:Ljava/lang/String;

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;FFFFLg4/p0;Landroid/net/Uri;Ljava/lang/String;I)V
    .locals 1

    .line 1
    sget v0, Li40/o3;->a:F

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Li40/n3;->d:Lx2/s;

    .line 7
    .line 8
    iput p2, p0, Li40/n3;->e:F

    .line 9
    .line 10
    iput p3, p0, Li40/n3;->f:F

    .line 11
    .line 12
    iput p4, p0, Li40/n3;->g:F

    .line 13
    .line 14
    iput p5, p0, Li40/n3;->h:F

    .line 15
    .line 16
    iput-object p6, p0, Li40/n3;->i:Lg4/p0;

    .line 17
    .line 18
    iput-object p7, p0, Li40/n3;->j:Landroid/net/Uri;

    .line 19
    .line 20
    iput-object p8, p0, Li40/n3;->k:Ljava/lang/String;

    .line 21
    .line 22
    iput p9, p0, Li40/n3;->l:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget v0, Li40/o3;->a:F

    .line 2
    .line 3
    move-object v9, p1

    .line 4
    check-cast v9, Ll2/o;

    .line 5
    .line 6
    check-cast p2, Ljava/lang/Integer;

    .line 7
    .line 8
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget p1, p0, Li40/n3;->l:I

    .line 12
    .line 13
    or-int/lit8 p1, p1, 0x1

    .line 14
    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v10

    .line 19
    iget-object v1, p0, Li40/n3;->d:Lx2/s;

    .line 20
    .line 21
    iget v2, p0, Li40/n3;->e:F

    .line 22
    .line 23
    iget v3, p0, Li40/n3;->f:F

    .line 24
    .line 25
    iget v4, p0, Li40/n3;->g:F

    .line 26
    .line 27
    iget v5, p0, Li40/n3;->h:F

    .line 28
    .line 29
    iget-object v6, p0, Li40/n3;->i:Lg4/p0;

    .line 30
    .line 31
    iget-object v7, p0, Li40/n3;->j:Landroid/net/Uri;

    .line 32
    .line 33
    iget-object v8, p0, Li40/n3;->k:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static/range {v1 .. v10}, Li40/o3;->a(Lx2/s;FFFFLg4/p0;Landroid/net/Uri;Ljava/lang/String;Ll2/o;I)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0
.end method
