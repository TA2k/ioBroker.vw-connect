.class public final Luu/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# instance fields
.field public final synthetic d:Luu/m1;

.field public final synthetic e:Lw3/a;


# direct methods
.method public constructor <init>(Luu/m1;Lw3/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/p0;->d:Luu/m1;

    .line 5
    .line 6
    iput-object p2, p0, Luu/p0;->e:Lw3/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 1

    .line 1
    iget-object v0, p0, Luu/p0;->d:Luu/m1;

    .line 2
    .line 3
    iget-object p0, p0, Luu/p0;->e:Lw3/a;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
