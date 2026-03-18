.class public final Luq/b;
.super Llp/y9;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Landroid/content/Context;

.field public final synthetic b:Landroid/text/TextPaint;

.field public final synthetic c:Llp/y9;

.field public final synthetic d:Luq/c;


# direct methods
.method public constructor <init>(Luq/c;Landroid/content/Context;Landroid/text/TextPaint;Llp/y9;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luq/b;->d:Luq/c;

    .line 5
    .line 6
    iput-object p2, p0, Luq/b;->a:Landroid/content/Context;

    .line 7
    .line 8
    iput-object p3, p0, Luq/b;->b:Landroid/text/TextPaint;

    .line 9
    .line 10
    iput-object p4, p0, Luq/b;->c:Llp/y9;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final b(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Luq/b;->c:Llp/y9;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Llp/y9;->b(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(Landroid/graphics/Typeface;Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Luq/b;->a:Landroid/content/Context;

    .line 2
    .line 3
    iget-object v1, p0, Luq/b;->b:Landroid/text/TextPaint;

    .line 4
    .line 5
    iget-object v2, p0, Luq/b;->d:Luq/c;

    .line 6
    .line 7
    invoke-virtual {v2, v0, v1, p1}, Luq/c;->f(Landroid/content/Context;Landroid/text/TextPaint;Landroid/graphics/Typeface;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Luq/b;->c:Llp/y9;

    .line 11
    .line 12
    invoke-virtual {p0, p1, p2}, Llp/y9;->c(Landroid/graphics/Typeface;Z)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
