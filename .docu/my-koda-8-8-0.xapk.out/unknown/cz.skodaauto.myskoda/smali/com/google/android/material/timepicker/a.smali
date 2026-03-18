.class public abstract Lcom/google/android/material/timepicker/a;
.super Ld6/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Le6/c;


# direct methods
.method public constructor <init>(Landroid/content/Context;I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ld6/b;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Le6/c;

    .line 5
    .line 6
    const/16 v1, 0x10

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-direct {v0, v1, p1}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lcom/google/android/material/timepicker/a;->d:Le6/c;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public d(Landroid/view/View;Le6/d;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 2
    .line 3
    iget-object v1, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 4
    .line 5
    invoke-virtual {v0, p1, v1}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/android/material/timepicker/a;->d:Le6/c;

    .line 9
    .line 10
    invoke-virtual {p2, p0}, Le6/d;->b(Le6/c;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
