.class public final Lh/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld/b;


# instance fields
.field public final synthetic a:Lcz/skodaauto/myskoda/app/main/system/MainActivity;


# direct methods
.method public constructor <init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh/h;->a:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lb/r;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh/h;->a:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p1}, Lh/n;->d()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lb/r;->getSavedStateRegistry()Lra/d;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "androidx:appcompat"

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lra/d;->a(Ljava/lang/String;)Landroid/os/Bundle;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Lh/n;->g()V

    .line 20
    .line 21
    .line 22
    return-void
.end method
