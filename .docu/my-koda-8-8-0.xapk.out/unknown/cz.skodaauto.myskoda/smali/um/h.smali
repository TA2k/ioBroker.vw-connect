.class public final synthetic Lum/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lum/i;


# instance fields
.field public final synthetic a:Lum/j;

.field public final synthetic b:I


# direct methods
.method public synthetic constructor <init>(Lum/j;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lum/h;->a:Lum/j;

    .line 5
    .line 6
    iput p2, p0, Lum/h;->b:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget-object v0, p0, Lum/h;->a:Lum/j;

    .line 2
    .line 3
    iget p0, p0, Lum/h;->b:I

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lum/j;->k(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
