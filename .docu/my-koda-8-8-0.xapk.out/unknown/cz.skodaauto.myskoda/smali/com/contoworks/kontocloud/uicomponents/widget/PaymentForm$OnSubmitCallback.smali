.class public interface abstract Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x609
    name = "OnSubmitCallback"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;
    }
.end annotation


# virtual methods
.method public abstract onBeforeSubmit(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;)V
.end method

.method public abstract onCancel()V
.end method

.method public abstract onError(Ljava/lang/String;)V
.end method

.method public abstract onSuccess(Ljava/lang/String;Ljava/lang/String;)V
.end method

.method public abstract onSuccess(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
.end method
